from argparse import ArgumentParser
import asyncio
import base64
import datetime
import requests

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel
from rich.align import Align
from rich.panel import Panel
from rich.text import Text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel import SQLModel, Field, Relationship, select
from sqlmodel.ext.asyncio.session import AsyncSession
from textual import events, work
from textual.app import App, ComposeResult
from textual.widgets import (
    Header, 
    RichLog,
    TextArea,
)
import websockets


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


class UserInfo(SQLModel, table=True):
    """Data model to represent user information."""

    name: str = Field(primary_key=True)
    identity_key: bytes # Given to other users to establish conversations
    authentication_key: str  # Used to authenticate with the server


class Ratchet(SQLModel, table=True):
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
    skipped_keys: list["SkippedKey"] = Relationship(back_populates="ratchet")
    messages: list["Message"] = Relationship(back_populates="ratchet")

    def skip_keys(self, until: int) -> list["SkippedKey"]:
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
                    ratchet_id=self.id,
                    dh=self.dh_received,
                    n=self.num_received,
                    mk=mk
                )
            )
            self.num_received += 1

        return keys

    def dh_ratchet(self, dh_received: X25519PublicKey) -> None:
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
    ratchet_id: int = Field(foreign_key="ratchet.id")
    dh: bytes
    n: int
    mk: bytes

    # Relationships
    ratchet: "Ratchet" = Relationship(back_populates="skipped_keys")


class Message(SQLModel, table=True):
    """Data model to store messages for a given recipient in the database."""

    id: int | None = Field(default=None, primary_key=True)
    ratchet_id: int = Field(foreign_key="ratchet.id")
    content: str
    timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC))
    sent: bool = Field(default=True)

    # Relationships
    ratchet: "Ratchet" = Relationship(back_populates="messages")


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
            return base64.b64decode(self.dh) \
                + self.pn.to_bytes(4) \
                + self.n.to_bytes(4) \
                + self.timestamp.isoformat().encode()

    header: Header
    ciphertext: str


class Conversation:

    def __init__(self, engine: AsyncEngine, ratchet_id: int):

        self.engine: AsyncEngine = engine
        self.ratchet_id: int = ratchet_id

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
            ratchet = Ratchet(
                name=peer_name, 
                identity_key=peer_identity.public_bytes_raw(),
                dh_sent=DHs.private_bytes_raw(),
                dh_received=DHr.public_bytes_raw(),
                root_key=RK,
                chain_key_sent=CKs,
                chain_key_received=CKr,
                AD=AD
            )
            session.add(ratchet)
            await session.commit()
            await session.refresh(ratchet)

        return cls(engine, ratchet.id)

    async def send_message(
        self, 
        content: str,
        websocket: websockets.ClientConnection | None = None
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
            ratchet = await session.get(Ratchet, self.ratchet_id)
            if ratchet is None:
                raise ValueError("Peer not found")

            # Get next message key and send chain key
            ratchet.chain_key_sent, mk = ck_kdf(ratchet.chain_key_sent)

            # Load the most recent DH public key to attach to message
            DHs = X25519PrivateKey.from_private_bytes(ratchet.dh_sent)
            DH = base64.b64encode(DHs.public_key().public_bytes_raw()).decode()

            # Prepare the message to be sent.
            header = TransmittedMessage.Header(
                dh=DH,
                pn=ratchet.prev_num_sent,
                n=ratchet.num_sent,
                timestamp=datetime.datetime.now(datetime.UTC)
            )
            ciphertext = AESGCMSIV(mk).encrypt(
                bytearray(12),
                content.encode(),
                ratchet.AD + header.encode()
            )
            transmitted_message = TransmittedMessage(
                header=header,
                ciphertext=base64.b64encode(ciphertext).decode()
            )

            # Try to send the message over the websocket
            if websocket is not None:
                await websocket.send(transmitted_message.model_dump_json())

            # Only store the message and update the conversation state if the send was successful
            ratchet.num_sent += 1
            session.add(ratchet)

            message = Message(
                ratchet_id=ratchet.id,
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
            ratchet = await session.get(Ratchet, self.ratchet_id)
            if ratchet is None:
                raise ValueError("Peer not found")

            # Try to get message key from database
            result = (await session.exec(statement)).one_or_none()
            if result is not None:
                mk = result.mk
                await session.delete(result)

            # No message key found, so compute
            else:
                # If received header doesn't match, store keys and ratchet
                if dh != ratchet.dh_received:
                    for sk in ratchet.skip_keys(transmitted_message.header.pn):
                        session.add(sk)
                    ratchet.dh_ratchet(X25519PublicKey.from_public_bytes(dh))

                # Once ratchet is complete, store keys up until expected N
                for sk in ratchet.skip_keys(transmitted_message.header.n):
                    session.add(sk)

                # Get message key and new receiving chain key
                ratchet.chain_key_received, mk = ck_kdf(ratchet.chain_key_received)
                ratchet.num_received += 1

                session.add(ratchet)

            # Decrypt ciphertext with message key
            plaintext = AESGCMSIV(mk).decrypt(
                bytearray(12),
                base64.b64decode(transmitted_message.ciphertext),
                ratchet.AD + transmitted_message.header.encode()
            ).decode()

            # Create stored message object and commit
            message = Message(
                ratchet_id=ratchet.id,
                content=plaintext,
                timestamp=transmitted_message.header.timestamp,
                sent=False
            )
            session.add(message)

            await session.commit()

        return plaintext

    async def messages(self):
        async with AsyncSession(self.engine) as session:
            result = await session.exec(
                select(Message).where(Message.ratchet_id == self.ratchet_id).order_by(Message.timestamp)
            )
            return result.all()


class ChatInput(TextArea):

    def _on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            self.post_message(self.Submitted(self, self.text))
            event.prevent_default()
            return

        super()._on_key(event)

    class Submitted(events.Message):
        def __init__(self, text_area: "ChatInput", value: str) -> None:
            self.text_area = text_area
            self.value = value
            super().__init__()


class DreamClient(App):

    MIN_INPUT_HEIGHT = 3
    MAX_INPUT_HEIGHT = 8

    CSS_PATH = "client.tcss"
    TITLE = "Dream Client"

    def __init__(
        self, 
        server_host: str, 
        server_port: int, 
        user_name: str,
        recipient_name: str,
        *args, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)

        self.host = server_host
        self.port = server_port
        self.username = user_name
        self.recipient = recipient_name

        self.engine: AsyncEngine | None = None
        self.websocket: websockets.ClientConnection | None = None
        self.conversation: Conversation | None = None
        
    def compose(self) -> ComposeResult:
        """Compose the UI elements of the app."""
        
        yield Header(icon="💭")
        yield RichLog(auto_scroll=True, wrap=True, min_width=24)
        yield ChatInput(placeholder=f"Message {self.recipient}...", id="message-box")
        self.sub_title = f"Chat with {self.recipient}"

    async def on_mount(self) -> None:
        """Initializes the app after mounting."""

        await self.setup_database()
        self.open_websocket()
        self.resize_chat_input()
        self.query_one(ChatInput).focus()

    async def setup_database(self) -> None:
        """Ensures that the local database is set up and the user is registered.
        Also attempts to load state of the conversation. 
        """

        # Ensure engine and metadata setup
        if self.engine is None:
            self.engine = create_async_engine(f"sqlite+aiosqlite:///{self.username}.db")
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        async with AsyncSession(self.engine) as session:
            # Check for an existing ratchet for the recipient
            query = select(Ratchet).where(Ratchet.name == self.recipient)
            ratchet = (await session.exec(query)).one_or_none()
            if ratchet:
                self.conversation = Conversation(
                    engine=self.engine,
                    ratchet_id=ratchet.id
                )
                return  # Existing conversation ensures existing user

            # Check if the user is already registered in the local database
            user_info = await session.get(UserInfo, self.username)
            if not user_info:
                raise RuntimeError("User not registered in the local database.")

    @work(exclusive=True)
    async def open_websocket(self) -> None:
        """Opens a websocket and listens for incoming messages."""

        # Get the user's authentication key from the local database
        async with AsyncSession(self.engine) as session:
            user_info = await session.get(UserInfo, self.username)
            auth = user_info.authentication_key
        
        try:
            url = f"ws://{self.host}:{self.port}/{self.recipient}/chat"
            async with websockets.connect(url, additional_headers={"token": auth}) as ws:
                self.websocket = ws
                async for raw in ws:
                    message = TransmittedMessage.model_validate_json(raw)
                    if not self.conversation:
                        await self.setup_conversation(message)
                    await self.conversation.receive_message(message)
                    await self.render_messages() 
        except websockets.ConnectionClosed:
            self.notify("Connection closed.")
        finally:
            self.websocket = None

    async def on_chat_input_submitted(self, event: ChatInput.Submitted) -> None:
        """Handles the submission of a chat message from the input box."""
        
        message = event.value.strip()
        if not message:
            return
        event.text_area.clear()

        if not self.conversation:
            await self.setup_conversation()
        await self.conversation.send_message(message, self.websocket)
        await self.render_messages()

    async def setup_conversation(
        self, 
        initial_message: TransmittedMessage = None
    ) -> None:
        """Creates a new conversation with the recipient."""

        # Get own identity key from the local database
        async with AsyncSession(self.engine) as session:
            user_info = await session.get(UserInfo, self.username)
            own_id = X25519PrivateKey.from_private_bytes(user_info.identity_key)

        # Get the peer's identity key from the server
        url = f"http://{self.host}:{self.port}/{self.recipient}/id"
        peer_id_bytes = base64.b64decode(requests.get(url).content)
        peer_id = X25519PublicKey.from_public_bytes(peer_id_bytes)

        # Process the initial message if it exists
        if initial_message:
            dh_bytes = base64.b64decode(initial_message.header.dh)
            dh = X25519PublicKey.from_public_bytes(dh_bytes)
        else:
            dh = None

        self.conversation = await Conversation.create(
            engine=self.engine,
            own_identity=own_id,
            peer_name=self.recipient,
            peer_identity=peer_id,
            initial_dh_key=dh
        )

    async def render_messages(self) -> None:
        log = self.query_one(RichLog)
        log.clear()
        if not self.conversation:
            return

        for message in await self.conversation.messages():
            # Calculate width for bubble
            log_width = self.query_one(RichLog).size.width
            usable_width = max(log_width - 6, 20)
            bubble_width = min(60, usable_width)

            # Create the message bubble based on whether the message was sent or received
            message_bubble = Panel(
                Text(message.content),
                border_style="#7AA9ED" if message.sent else "white",
                expand=False,
                width=bubble_width,
                padding=(0, 1)
            )
            log_entry = Align(
                message_bubble,
                align="right" if message.sent else "left"
            )

            # Write the message bubble to the chat log
            self.query_one(RichLog).write(log_entry, expand=True, animate=True)

    def resize_chat_input(self) -> None:
        message_box = self.query_one(ChatInput)

        # Calculate the height needed for the message box based on its content
        wrapped_height = max(message_box.wrapped_document.height, 1)
        target_height = min(
            max(wrapped_height + 2, self.MIN_INPUT_HEIGHT),
            self.MAX_INPUT_HEIGHT,
        )

        # Apply the calculated height to the message box
        message_box.styles.height = target_height

    def on_text_area_changed(self, _: TextArea.Changed) -> None:
        self.resize_chat_input()

    async def on_resize(self, _: events.Resize) -> None:
        self.resize_chat_input()
        await self.render_messages()


async def register_user(host: str, port: int, username: str):

    engine = create_async_engine(f"sqlite+aiosqlite:///{username}.db")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    async with AsyncSession(engine) as session:
        user = await session.get(UserInfo, username)
        if user is not None:
            print("User already exists, skipping registration.")
            return  # User already exists, no need to register again

        # Generate new identity key for the user
        identity_key = X25519PrivateKey.generate()
        private_key_bytes = identity_key.private_bytes_raw()
        public_key_bytes = identity_key.public_key().public_bytes_raw()
        public_key_b64 = base64.b64encode(public_key_bytes).decode()
        
        # Send registration request to the server
        endpoint = f"http://{host}:{port}/register"
        response = requests.post(
            endpoint,
            json={
                "username": username, 
                "identity": public_key_b64
            }
        )
        jwt = response.text.removeprefix('"').removesuffix('"')

        # Check if the server successfully registered the user
        if response.status_code != 201:
            raise RuntimeError("Failed to register user with server.")

        # Add the new user information to the local database
        user_info = UserInfo(
            name=username,
            identity_key=private_key_bytes,
            authentication_key=jwt
        )
        session.add(user_info)
        await session.commit()


if __name__ == "__main__":
    parser = ArgumentParser(description="Dream Messenger Client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Register a user")
    register_parser.add_argument("--host", type=str, default="localhost", help="Server host")
    register_parser.add_argument("--port", type=int, default=8000, help="Server port")
    register_parser.add_argument("username", type=str, help="Username to register")

    message_parser = subparsers.add_parser("message", help="Message a recipient")
    message_parser.add_argument("--host", type=str, default="localhost", help="Server host")
    message_parser.add_argument("--port", type=int, default=8000, help="Server port")
    message_parser.add_argument("--username", type=str, default=None, help="The username to use (looks for database if not provided)")
    message_parser.add_argument("recipient", type=str, help="Recipient username")
    args = parser.parse_args()

    if args.command == "register":
        asyncio.run(register_user(args.host, args.port, args.username))
    elif args.command == "message":
        # TODO: Implement logic to lookup username in local config
        if args.username is None:
            args.username = "alice"

        if args.username == args.recipient:
            raise RuntimeError("Cannot message yourself.")

        client = DreamClient(
            server_host=args.host,
            server_port=args.port,
            user_name=args.username,
            recipient_name=args.recipient
        )
        client.run()