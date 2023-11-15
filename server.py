import time
from hmac import compare_digest
import os
from .lib import decrypt, encrypt, E_ECDH
from wallycore import ec_private_key_verify, ec_sig_from_bytes, sha256, \
    hmac_sha256, EC_FLAG_ECDSA, ec_private_key_bip341_tweak, ec_public_key_from_private_key


class PINServerECDH(E_ECDH):
    STATIC_SERVER_PRIVATE_KEY_FILE = 'server_private_key.key'
    STATIC_SERVER_PUBLIC_KEY_FILE = 'server_public_key.pub'
    STATIC_SERVER_PRIVATE_KEY = None
    STATIC_SERVER_AES_PIN_DATA = None

    @classmethod
    def generate_server_key_pair(cls):
        if os.path.exists(cls.STATIC_SERVER_PRIVATE_KEY_FILE):
            print(f'Key already exists in file {cls.STATIC_SERVER_PRIVATE_KEY_FILE}')
            return

        private_key, public_key = cls.generate_ec_key_pair()

        with open(cls.STATIC_SERVER_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key)

        with open(cls.STATIC_SERVER_PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key)

        print(f'New private key written to file {cls.STATIC_SERVER_PRIVATE_KEY_FILE}')
        print(f'New public key written to file {cls.STATIC_SERVER_PUBLIC_KEY_FILE}')

    @classmethod
    def load_private_key(cls):
        if not cls.STATIC_SERVER_PRIVATE_KEY:
            with open(cls.STATIC_SERVER_PRIVATE_KEY_FILE, 'rb') as f:
                cls.STATIC_SERVER_PRIVATE_KEY = f.read()
                ec_private_key_verify(cls.STATIC_SERVER_PRIVATE_KEY)

    @classmethod
    def _sign_with_static_key(cls, msg):
        assert cls.STATIC_SERVER_PRIVATE_KEY

        hashed = sha256(msg)
        return ec_sig_from_bytes(cls.STATIC_SERVER_PRIVATE_KEY,
                                 hashed,
                                 EC_FLAG_ECDSA)

    @classmethod
    def _get_aes_pin_data_key(cls):
        assert cls.STATIC_SERVER_PRIVATE_KEY

        if not cls.STATIC_SERVER_AES_PIN_DATA:
            cls.STATIC_SERVER_AES_PIN_DATA = hmac_sha256(cls.STATIC_SERVER_PRIVATE_KEY, b'pin_data')
        return cls.STATIC_SERVER_AES_PIN_DATA

    # Instance methods
    def __init__(self):
        super().__init__()
        self.time_started = int(time.time())


# NOTE: protocol v1:
# Explicit 'hmac' fields, separate derived keys, and key-exchange handshake
class PINServerECDHv1(PINServerECDH):
    def __init__(self):
        super().__init__()

    def get_signed_public_key(self):
        return self.public_key, self._sign_with_static_key(self.public_key)

    # Decrypt the received payload (ie. aes-key)
    def decrypt_request_payload(self, cke, encrypted, hmac):
        # Verify hmac received
        hmac_calculated = hmac_sha256(self.request_hmac_key, cke + encrypted)
        assert compare_digest(hmac, hmac_calculated)

        # Return decrypted data
        return decrypt(self.request_encryption_key, encrypted)

    def encrypt_response_payload(self, payload):
        encrypted = encrypt(self.response_encryption_key, payload)
        hmac = hmac_sha256(self.response_hmac_key, encrypted)
        return encrypted, hmac

    # Function to deal with wrapper ecdh encryption.
    # Calls passed function with unwrapped payload, and wraps response before
    # returning.  Separates payload handler func from wrapper encryption.
    def call_with_payload(self, cke, encrypted, hmac, func):
        self.generate_shared_secrets(cke)
        payload = self.decrypt_request_payload(cke, encrypted, hmac)

        # Call the passed function with the decrypted payload
        response = func(cke, payload, self._get_aes_pin_data_key())

        encrypted, hmac = self.encrypt_response_payload(response)
        return encrypted, hmac


# NOTE: protocol v2:
# 'hmac' fields and derived keys implicit, and no key-exchange handshake required
class PINServerECDHv2(PINServerECDH):

    @classmethod
    def generate_ec_key_pair(cls, replay_counter, cke):
        assert cls.STATIC_SERVER_PRIVATE_KEY

        tweak = sha256(hmac_sha256(cke, replay_counter))
        private_key = ec_private_key_bip341_tweak(cls.STATIC_SERVER_PRIVATE_KEY, tweak, 0)
        ec_private_key_verify(private_key)
        public_key = ec_public_key_from_private_key(private_key)
        return private_key, public_key

    def __init__(self, replay_counter, cke):
        # intentionally we don't call any constructor from what we inherit from
        assert len(replay_counter) == 4
        self.replay_counter = replay_counter
        self.private_key, self.public_key = self.generate_ec_key_pair(replay_counter, cke)

    def decrypt_request_payload(self, cke, encrypted):
        return self.decrypt_with_ecdh(cke, self.LABEL_ORACLE_REQUEST, encrypted)

    def encrypt_response_payload(self, cke, payload):
        return self.encrypt_with_ecdh(cke, self.LABEL_ORACLE_RESPONSE, payload)

    # Function to deal with wrapper ecdh encryption.
    # Calls passed function with unwrapped payload, and wraps response before
    # returning.  Separates payload handler func from wrapper encryption.
    def call_with_payload(self, cke, encrypted, func):
        payload = self.decrypt_request_payload(cke, encrypted)
        response = func(cke, payload, self._get_aes_pin_data_key(), self.replay_counter)
        return self.encrypt_response_payload(cke, response)
