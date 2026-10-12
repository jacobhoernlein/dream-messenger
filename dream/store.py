import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlmodel import SQLModel, Field, Relationship, Session, select
from sqlalchemy import Engine


class Peer(SQLModel, table=True):
    """Data model to representing a peer, including the Double Ratchet
    state.
    """

    id: int | None= Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    identity_key: bytes

    # Double Ratchet state for this peer
    DHs: bytes
    DHr: bytes
    RK: bytes
    CKs: bytes
    CKr: bytes | None = None
    AD: bytes
    Ns: int = 0
    Nr: int = 0
    PN: int = 0

    # Relationships
    message_keys: list["MessageKey"] = Relationship(back_populates="peer")
    messages: list["Message"] = Relationship(back_populates="peer")


class MessageKey(SQLModel, table=True):
    """Data model to store message keys for a given recipient in the 
    database.
    """

    id: int | None = Field(default=None, primary_key=True)
    peer_id: int = Field(foreign_key="peer.id")
    DHr: bytes
    N: int
    mk: bytes

    # Relationships
    peer: "Peer" = Relationship(back_populates="message_keys")


class Message(SQLModel, table=True):
    """Data model to store messages for a given recipient in the database."""

    id: int | None = Field(default=None, primary_key=True)
    peer_id: int = Field(foreign_key="peer.id")
    content: str
    timestamp: datetime.datetime

    # Relationships
    peer: "Peer" = Relationship(back_populates="messages")


class Conversation:

    def __init__(self, engine: Engine, peer: Peer):

        self.engine: Engine = engine
        self.peer: Peer = peer

    @staticmethod
    def __kdf_rk(root_key: bytes, dh_key: bytes) -> tuple[bytes, bytes]:
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

    @staticmethod
    def __kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
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

    @classmethod
    def load(cls, engine: Engine, peer_id: int | str):
        """Load a conversation from the database for the given peer.

        Args:
            peer (int | str): The ID or name of the peer.

        Returns:
            Conversation: The loaded conversation object.
        """

        with Session(engine) as session:
            if isinstance(peer_id, int):
                peer = session.get(Peer, peer_id)
            else:
                peer = session.exec(select(Peer).filter(Peer.name == peer_id)).first()

        if peer is None:
            raise ValueError("Peer not found")

        return cls(engine, peer)

    @classmethod
    def create(cls, 
        engine: Engine, 
        name: str, 
        identity: X25519PrivateKey,
        peer_identity: X25519PublicKey
    ):
        """Create a new conversation with the given peer based on the
        provided identity keys.
        
        Args:
            engine (Engine): The database engine.
            name (str): The name of the peer.
            identity (X25519PrivateKey): The sender's identity key.
            peer_identity (X25519PublicKey): The receiver's identity key.

        Returns:
            Conversation: The newly created conversation object.
        """

        # Initial shared secret and associated data based on identity keys
        SK = identity.exchange(peer_identity)
        AD = identity.public_key().public_bytes_raw() + peer_identity.public_bytes_raw()

        # Generate first send chain key and store root key
        DHs = X25519PrivateKey.generate()
        RK, CKs = cls.__kdf_rk(SK, DHs.exchange(peer_identity))

        with Session(engine) as session:
            peer = Peer(
                name=name, 
                identity_key=identity.public_key().public_bytes_raw(),
                DHs=DHs.private_bytes_raw(),
                RK=RK,
                CKs=CKs,
                AD=AD
            )
            session.add(peer)
            session.commit()
            session.refresh(peer)

        return cls(engine, peer)