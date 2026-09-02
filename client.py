from .lib import E_ECDH, decrypt, encrypt
from hmac import compare_digest
from werkzeug.exceptions import SecurityError
from wallycore import ec_sig_verify, sha256, hmac_sha256, EC_FLAG_ECDSA, \
                      ec_public_key_bip341_tweak


class PINClientECDH(E_ECDH):

    def __init__(self, static_server_public_key):
        super().__init__()
        self.static_server_public_key = static_server_public_key
        self.ecdh_server_public_key = None

    # returns ske, cke
    def get_key_exchange(self):
        return self.ecdh_server_public_key, self.public_key


# NOTE: protocol v1:
# Explicit 'hmac' fields, separate derived keys, and key-exchange handshake
class PINClientECDHv1(PINClientECDH):
    def handshake(self, e_ecdh_server_public_key, static_server_signature):
        ec_sig_verify(
            self.static_server_public_key,
            sha256(e_ecdh_server_public_key),
            EC_FLAG_ECDSA,
            static_server_signature)

        # Store the ecdh server public key (ske)
        self.ecdh_server_public_key = e_ecdh_server_public_key

        # Cache the shared secrets
        self.generate_shared_secrets(e_ecdh_server_public_key)

    # Encrypt/sign/hmac the payload (ie. the pin secret)
    def encrypt_request_payload(self, payload):
        assert self.ecdh_server_public_key

        encrypted = encrypt(self.request_encryption_key, payload)
        hmac = hmac_sha256(self.request_hmac_key, self.public_key + encrypted)
        return encrypted, hmac

    # Decrypt the received payload (ie. aes-key)
    def decrypt_response_payload(self, encrypted, hmac):
        assert self.ecdh_server_public_key

        # Verify hmac received
        hmac_calculated = hmac_sha256(self.response_hmac_key, encrypted)
        if not compare_digest(hmac, hmac_calculated):
            raise SecurityError()

        # Return decrypted data
        return decrypt(self.response_encryption_key, encrypted)


# NOTE: protocol v2:
# 'hmac' fields and derived keys implicit, and no key-exchange handshake required
class PINClientECDHv2(PINClientECDH):

    def __init__(self, static_server_public_key, replay_counter):
        super().__init__(static_server_public_key)

        assert len(replay_counter) == 4
        self.replay_counter = replay_counter

        # Derive and store the ecdh server public key (ske)
        tweak = sha256(hmac_sha256(self.public_key, self.replay_counter))
        self.ecdh_server_public_key = ec_public_key_bip341_tweak(
                self.static_server_public_key, tweak, 0)

    def encrypt_request_payload(self, payload):
        return self.encrypt_with_ecdh(self.ecdh_server_public_key, self.LABEL_ORACLE_REQUEST,
                                      payload)

    def decrypt_response_payload(self, encrypted):
        return self.decrypt_with_ecdh(self.ecdh_server_public_key, self.LABEL_ORACLE_RESPONSE,
                                      encrypted)
