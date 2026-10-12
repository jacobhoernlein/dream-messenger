from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class Message:

    @dataclass
    class Header:

        DH: X25519PublicKey # The current DH public key of sender
        PN: int             # Previous chain length
        N:  int             # Message number
        timestamp: datetime

        def encode(self) -> bytes:
            return self.DH.public_bytes_raw() + self.PN.to_bytes(4) + self.N.to_bytes(4) + self.timestamp.isoformat().encode()

    header: Header
    ciphertext: bytes


class DoubleRatchet:

    def __init__(
        self,
        DHs: X25519PrivateKey,
        DHr: X25519PublicKey,
        RK: bytes,
        CKs: bytes,
        CKr: bytes,
        AD: bytes,
        Ns: int=0,
        Nr: int=0,
        PN: int=0,
        MKSKIPPED: dict[tuple[X25519PublicKey, int], bytes]=None,
    ):
        """Creates a new DoubleRatchet state object.
        
        Args:
            DHs (X25519PrivateKey): The sending DH keypair
            DHr (X25519PublicKey): The receiving DH keypair
            RK (bytes): Root key
            CKs (bytes): Sending chain key
            CKr (bytes): Receiving chain key
            AD (bytes): Associated data to be used with AES-GCM-SIV
            Ns (int): Number of messages sent
            Nr (int): Number of messages received
            PN (int): Number of messages in previous sending chain
            MKSKIPPED (dict): Dictionary of skipped message keys
        """
        
        self.DHs = DHs
        self.DHr = DHr
        self.RK = RK
        self.CKs = CKs
        self.CKr = CKr
        self.AD = AD
        self.Ns = Ns
        self.Nr = Nr
        self.PN = PN
        self.MKSKIPPED = {} if MKSKIPPED is None else MKSKIPPED

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

    def __skip_keys(self, until: int) -> None:
        """Skips keys until given N is reached in receiving chain, 
        storing those keys in the dictionary

        Args:
            until (int): Number of keys to generate until

        Returns:
            None
        """

        if until > self.Nr + 1000:
            raise ValueError("Max skips exceeded.")
        if self.CKr is not None:
            while self.Nr < until:
                self.CKr, message_key = self.__kdf_ck(self.CKr)
                self.MKSKIPPED[(self.DHr.public_bytes_raw(), self.Nr)] = message_key
                self.Nr += 1

    def __dh_ratchet(self, DHr: X25519PublicKey) -> None:
        """Performs a Diffie-Hellman ratchet based on new DHr
        
        Args:
            DHr: The new public key
            
        Returns:
            None
        """

        # Ratchet recieve and send chain keys based on received public key
        self.RK, self.CKr = self.__kdf_rk(self.RK, self.DHs.exchange(DHr))
        self.DHs = X25519PrivateKey.generate()
        self.RK, self.CKs = self.__kdf_rk(self.RK, self.DHs.exchange(DHr))

        # Reset other state data
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr = DHr

    @classmethod
    def init_conversation(
        cls, 
        IDi: X25519PrivateKey, 
        IDr: X25519PublicKey
    ):
        """Create a new DoubleRatchet object by initiating a 
        conversation with a recipient based on their identity key.
        
        Args:
            IDi (X25519PrivateKey): The initiator's identity keypair
            IDr (X25519PublicKey): The recipient's identity public key
        
        Returns:
            DoubleRatchet: The initial conversation state
        """

        # Initial shared secret and associated data based on identity keys
        SK = IDi.exchange(IDr)
        AD = IDi.public_key().public_bytes_raw() + IDr.public_bytes_raw()

        # Generate first send chain key and store root key
        DHs = X25519PrivateKey.generate()
        RK, CKs = cls.__kdf_rk(SK, DHs.exchange(IDr))

        return cls(DHs, IDr, RK, CKs, None, AD)        

    @classmethod
    def ack_conversation(
        cls,
        IDr: X25519PrivateKey,
        IDi: X25519PublicKey,
        DHr: X25519PublicKey
    ):
        """Create a new DoubleRatchet as a response to a received
        message.

        Args:
            IDr (X25519PrivateKey): The recipient's identity keypair
            IDi (X25519PublicKey): The initiator's identity key
            DHr (X25519PublicKey): The message's public key
            
        Returns
            DoubleRatchet: The initial conversation state
        """
        
        # Initial shared secret and associated data based on identity keys
        SK = IDr.exchange(IDi)
        AD = IDi.public_bytes_raw() + IDr.public_key().public_bytes_raw()

        # Generate receive and send chain keys based on received public key
        RK, CKr = cls.__kdf_rk(SK, IDr.exchange(DHr))
        DHs = X25519PrivateKey.generate()
        RK, CKs = cls.__kdf_rk(RK, DHs.exchange(DHr))

        return cls(DHs, DHr, RK, CKs, CKr, AD)

    def encrypt(self, raw_message: bytes) -> Message:
        """Encrypts a message and ratchets the send chain
        
        Args:
            message_text (bytes): The message to encrypt
            
        Returns:
            Message: The message object with header and AEAD ciphertext.
        """

        # Ratchet send key chain
        self.CKs, message_key = self.__kdf_ck(self.CKs)

        # Create header for message and authenticated ciphertext
        header = Message.Header(
            self.DHs.public_key(), 
            self.PN, 
            self.Ns, 
            datetime.now(timezone.utc)
        )
        ciphertext = AESGCMSIV(message_key).encrypt(
            bytearray(12),  # Keys are unique for each message, so nonce can be null.
            raw_message,
            self.AD + header.encode()
        )

        # Increment number sent before returning Message object
        self.Ns += 1
        return Message(header, ciphertext)
    
    def decrypt(self, message: Message) -> bytes:
        """Ratchets send chain and DH chain if necessary and decrypts 
        message.
        
        Args:
            message (Message): The message to decrypt

        Returns:
            bytes: The decrypted plaintext 
        """

        # Save state in case of failure during decryption
        DHs = self.DHs
        DHr = self.DHr
        RK = self.RK
        CKs = self.CKs
        CKr = self.CKr
        Ns = self.Ns
        Nr = self.Nr
        PN = self.PN
        MKSKIPPED = dict(self.MKSKIPPED)

        header = message.header
        ciphertext = message.ciphertext

        try:
            # Check if message key is already computed
            sk_key = header.DH.public_bytes_raw(), header.N
            if sk_key in self.MKSKIPPED:
                mk = self.MKSKIPPED[sk_key]
                del self.MKSKIPPED[sk_key]

            else:
                # If received header doesn't match, store keys and ratchet
                if message.header.DH.public_bytes_raw() != self.DHr.public_bytes_raw():
                    self.__skip_keys(message.header.PN)
                    self.__dh_ratchet(message.header.DH)

                # Once ratchet is complete, store keys up until expected N
                self.__skip_keys(message.header.N)

                # Get message key and new receiving chain key
                self.CKr, mk = self.__kdf_ck(self.CKr)
                self.Nr += 1

            return AESGCMSIV(mk).decrypt(
                bytearray(12),  # Nonce is null
                ciphertext,
                self.AD + header.encode()
            )

        # Restore state and raise exception on any error
        except Exception:
            self.DHs = DHs
            self.DHr = DHr
            self.RK = RK
            self.CKs = CKs
            self.CKr = CKr
            self.Ns = Ns
            self.Nr = Nr
            self.PN = PN
            self.MKSKIPPED = MKSKIPPED
            raise


if __name__ == "__main__":

    alice_id = X25519PrivateKey.generate()
    bob_id = X25519PrivateKey.generate()

    alice_state = DoubleRatchet.init_conversation(alice_id, bob_id.public_key())

    a1 = alice_state.encrypt(b"hello, bob!")

    bob_state = DoubleRatchet.ack_conversation(
        bob_id, 
        alice_id.public_key(), 
        a1.header.DH
    )

    b1 = bob_state.encrypt(b'Hi alice!')
    b2 = bob_state.encrypt(b'How are you?')

    alice_state.decrypt(b1)