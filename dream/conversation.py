import base64
import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import SQLModel, Field, Relationship, select
from sqlmodel.ext.asyncio.session import AsyncSession
from websockets.asyncio.client import ClientConnection


def rk_kdf(root_key: bytes, dh_key: bytes) -> tuple[bytes, bytes]:
    """Derive a new root key and chain key from the given root key 
    and DH key.
    
    Args:
        root_key (bytes): The current root key
        dh_key (bytes): The key output from the DH step
    
    Returns:
        tuple[bytes, bytes]: The new root key and chain key
    """

    # Uses HKDF as recommended by Signal spec
    kdf_out = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b"kdf_rk"
    ).derive(dh_key)

    return kdf_out[:32], kdf_out[32:]

def ck_kdf(chain_key: bytes) -> tuple[bytes, bytes]:
    """Derive a new chain key and message key from a given chain key.
    
    Args:
        chain_key (bytes): The current chain key

    Returns:
        tuple[bytes, bytes]: The new chain key and message key 
    """
    
    # Uses HMAC as recommended by Signal spec
    hmac = HMAC(
        key=chain_key,
        algorithm=hashes.SHA256()
    )
    hmac.update(b'chain_key')
    ck = hmac.copy().finalize()
    hmac.update(b'message_key')

    return ck, hmac.finalize()


class Peer(SQLModel, table=True):
    """Data model to representing a peer, including the Double Ratchet
    state.
    """

    id: int | None= Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    identity_key: bytes

    # Double Ratchet state for this peer
    dh_sent: bytes
    dh_received: bytes
    root_key: bytes
    chain_key_sent: bytes
    chain_key_received: bytes | None = None
    AD: bytes
    num_sent: int = 0
    num_received: int = 0
    prev_num_sent: int = 0

    # Relationships
    skipped_keys: list["SkippedKey"] = Relationship(back_populates="peer")
    messages: list["Message"] = Relationship(back_populates="peer")

    def skip_keys(self, until: int) -> list[SkippedKey]:
        """Skips keys until given N is reached in receiving chain, 
        storing those keys in the dictionary

        Args:
            until (int): Number of keys to generate until

        Returns:
            list[SkippedKey]: The list of keys that were skipped
        """

        keys = []
        if self.chain_key_received is None:
            return keys
        if until > self.num_received + 1000:
            raise ValueError("Max skips exceeded.")

        while self.num_received < until:
            self.chain_key_received, mk = ck_kdf(self.chain_key_received)
            keys.append(
                SkippedKey(
                    peer_id=self.id,
                    dh=self.dh_received,
                    n=self.num_received,
                    mk=mk
                )
            )
            self.num_received += 1

        return keys

    def ratchet(self, dh_received: X25519PublicKey) -> None:
        """Performs a Diffie-Hellman ratchet based on new DHr
        
        Args:
            dh_received (X25519PublicKey): The new public key
            
        Returns:
            None
        """

        # Update receive chain key
        self.dh_received = dh_received.public_bytes_raw()
        self.root_key, self.chain_key_received = rk_kdf(
            self.root_key, 
            X25519PrivateKey.from_private_bytes(self.dh_sent).exchange(dh_received)
        )

        dh_sent = X25519PrivateKey.generate()
        self.dh_sent = dh_sent.private_bytes_raw()
        self.root_key, self.chain_key_sent = rk_kdf(
            self.root_key, dh_sent.exchange(dh_received)
        )

        # Reset other state data
        self.prev_num_sent = self.num_sent
        self.num_sent = 0
        self.num_received = 0


class SkippedKey(SQLModel, table=True):
    """Data model to store message keys for a given recipient in the 
    database.
    """

    id: int | None = Field(default=None, primary_key=True)
    peer_id: int = Field(foreign_key="peer.id")
    dh: bytes
    n: int
    mk: bytes

    # Relationships
    peer: "Peer" = Relationship(back_populates="skipped_keys")


class Message(SQLModel, table=True):
    """Data model to store messages for a given recipient in the database."""

    id: int | None = Field(default=None, primary_key=True)
    peer_id: int = Field(foreign_key="peer.id")
    content: str
    timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC))
    sent_or_received: str = Field(default="sent", regex="^(sent|received)$")

    # Relationships
    peer: "Peer" = Relationship(back_populates="messages")


class TransmittedMessage(BaseModel):
    """Data model to represent a message that is transmitted over the 
    websocket connection.
    """

    class Header(BaseModel):
        dh: str
        pn: int
        n: int
        timestamp: datetime.datetime

        def encode(self) -> bytes:
            return base64.b64decode(self.dh) + self.pn.to_bytes(4) + self.n.to_bytes(4) + self.timestamp.isoformat().encode()

    header: Header
    ciphertext: str


class Conversation:

    def __init__(self, engine: AsyncEngine, peer_id: int):

        self.engine: AsyncEngine = engine
        self.peer_id: int = peer_id

    @classmethod
    async def create(cls, 
        engine: AsyncEngine, 
        own_identity: X25519PrivateKey,
        peer_name: str, 
        peer_identity: X25519PublicKey,
        initial_dh_key: X25519PublicKey | None = None
    ):
        """Create a new conversation with the given peer based on the
        provided identity keys. If initial_dh_key is given, the caller will be
        the recipient, and DHr will be populated.

        Args:
            engine (Engine): The database engine.
            peer_name (str): The name of the peer.
            own_identity (X25519PrivateKey): The sender's identity key.
            peer_identity (X25519PublicKey): The receiver's identity key.
            initial_dh_key (X25519PublicKey, optional): The initial DH key for the recipient. Defaults to None.

        Returns:
            Conversation: The newly created conversation object.
        """

        # Initial shared secret and associated data based on identity keys
        RK = own_identity.exchange(peer_identity)

        # If initial_dh_key is provided, we are the recipient and will 
        # derive CKr from it. Otherwise, we are the initiator and will
        # derive CKs from our own DHs.
        if initial_dh_key is not None:
            DHr = initial_dh_key
            RK, CKr = rk_kdf(RK, own_identity.exchange(DHr))
            AD = peer_identity.public_bytes_raw() + own_identity.public_key().public_bytes_raw()
        else:
            DHr = peer_identity
            CKr = None
            AD = own_identity.public_key().public_bytes_raw() + peer_identity.public_bytes_raw()

        # Generate first DHs and CKs for sending messages
        DHs = X25519PrivateKey.generate()
        RK, CKs = rk_kdf(RK, DHs.exchange(DHr))
        
        # Store the new peer and conversation state in the database
        async with AsyncSession(engine) as session:
            peer = Peer(
                name=peer_name, 
                identity_key=own_identity.public_key().public_bytes_raw(),
                dh_sent=DHs.private_bytes_raw(),
                dh_received=DHr.public_bytes_raw(),
                root_key=RK,
                chain_key_sent=CKs,
                chain_key_received=CKr,
                AD=AD
            )
            session.add(peer)
            await session.commit()
            await session.refresh(peer)
            peer_id = peer.id

        return cls(engine, peer_id)

    async def send_message(
        self, 
        content: str,
        websocket: ClientConnection | None = None
    ) -> TransmittedMessage:
        """Encrypt and send a message through the websocket connection 
        (if given), updating the conversation state in the database.

        Args:
            content (str): The content of the message to send.
            websocket (ClientConnection, optional): The websocket connection to send the message through.
            
        Returns:
            TransmittedMessage: The message that was encrypted.
        """

        async with AsyncSession(self.engine) as session:
            peer = await session.get(Peer, self.peer_id)
            if peer is None:
                raise ValueError("Peer not found")

            # Get next message key and send chain key
            peer.chain_key_sent, mk = ck_kdf(peer.chain_key_sent)

            # Load the most recent DH public key to attach to message
            DHs = X25519PrivateKey.from_private_bytes(peer.dh_sent)
            DH = base64.b64encode(DHs.public_key().public_bytes_raw()).decode()

            # Prepare the message to be sent.
            header = TransmittedMessage.Header(
                dh=DH,
                pn=peer.prev_num_sent,
                n=peer.num_sent,
                timestamp=datetime.datetime.now(datetime.UTC)
            )
            ciphertext = AESGCMSIV(mk).encrypt(
                bytearray(12),
                content.encode(),
                peer.AD + header.encode()
            )
            transmitted_message = TransmittedMessage(
                header=header,
                ciphertext=base64.b64encode(ciphertext).decode()
            )

            # Try to send the message over the websocket
            if websocket is not None:
                await websocket.send(transmitted_message.model_dump_json())

            # Only store the message and update the conversation state if the send was successful
            peer.num_sent += 1
            session.add(peer)

            message = Message(
                peer_id=peer.id,
                content=content,
                timestamp=header.timestamp
            )
            session.add(message)

            await session.commit()

        return transmitted_message

    async def receive_message(
        self,
        transmitted_message: TransmittedMessage
    ) -> str:
        """Decrypt a received message and update the conversation state in 
        the database.

        Args:
            transmitted_message (TransmittedMessage): The received message object.
        
        Returns:
            str: The decrypted plaintext message.
        """

        # Set up statement to find message key that is already generated
        dh = base64.b64decode(transmitted_message.header.dh)
        n = transmitted_message.header.n
        statement = select(SkippedKey).where(SkippedKey.dh == dh, SkippedKey.n == n)

        async with AsyncSession(self.engine) as session:
            peer = await session.get(Peer, self.peer_id)
            if peer is None:
                raise ValueError("Peer not found")

            # Try to get message key from database
            result = (await session.exec(statement)).one_or_none()
            if result is not None:
                mk = result.mk
                await session.delete(result)

            # No message key found, so compute
            else:
                # If received header doesn't match, store keys and ratchet
                if dh != peer.dh_received:
                    for sk in peer.skip_keys(transmitted_message.header.pn):
                        session.add(sk)
                    peer.ratchet(X25519PublicKey.from_public_bytes(dh))

                # Once ratchet is complete, store keys up until expected N
                for sk in peer.skip_keys(transmitted_message.header.n):
                    session.add(sk)

                # Get message key and new receiving chain key
                peer.chain_key_received, mk = ck_kdf(peer.chain_key_received)
                peer.num_received += 1

                session.add(peer)

            # Decrypt ciphertext with message key
            plaintext = AESGCMSIV(mk).decrypt(
                bytearray(12),
                base64.b64decode(transmitted_message.ciphertext),
                peer.AD + transmitted_message.header.encode()
            ).decode()

            # Create stored message object and commit
            message = Message(
                peer_id=peer.id,
                content=plaintext,
                timestamp=transmitted_message.header.timestamp,
                sent_or_received="received"
            )
            session.add(message)

            await session.commit()

        return plaintext

if __name__ == "__main__":

    async def main():
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine("sqlite+aiosqlite:///")
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        alice_identity = X25519PrivateKey.generate()
        bob_identity = X25519PrivateKey.generate()

        alice_with_bob = await Conversation.create(
            engine=engine,
            own_identity=alice_identity,
            peer_name="Bob",
            peer_identity=bob_identity.public_key()
        )
        a1 = await alice_with_bob.send_message("Hello, Bob!")

        bob_with_alice = await Conversation.create(
            engine=engine,
            own_identity=bob_identity,
            peer_name="Alice",
            peer_identity=alice_identity.public_key(),
            initial_dh_key=X25519PublicKey.from_public_bytes(base64.b64decode(a1.header.dh))
        )
        assert await bob_with_alice.receive_message(a1) == "Hello, Bob!"

        b1 = await bob_with_alice.send_message("Hello, Alice!")
        b2 = await bob_with_alice.send_message("How are you?")
        b3 = await bob_with_alice.send_message("Are you there?")

        assert await alice_with_bob.receive_message(b3) == "Are you there?"
        assert await alice_with_bob.receive_message(b2) == "How are you?"
        assert await alice_with_bob.receive_message(b1) == "Hello, Alice!"

        a1 = await alice_with_bob.send_message("Yes, I'm here!")
        b1 = await bob_with_alice.send_message("Great!")
        a2 = await alice_with_bob.send_message("How's it going?")

        assert await bob_with_alice.receive_message(a2) == "How's it going?"
        assert await alice_with_bob.receive_message(b1) == "Great!"
        assert await bob_with_alice.receive_message(a1) == "Yes, I'm here!"
        
    import asyncio
    asyncio.run(main())