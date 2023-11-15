import os

from wallycore import AES_BLOCK_LEN, AES_FLAG_DECRYPT, AES_FLAG_ENCRYPT, \
    aes_cbc, ec_private_key_verify, ec_public_key_from_private_key, ecdh, \
    hmac_sha256, aes_cbc_with_ecdh_key


def encrypt(aes_key, plaintext):
    iv = os.urandom(AES_BLOCK_LEN)
    encrypted = aes_cbc(aes_key, iv, plaintext, AES_FLAG_ENCRYPT)
    return iv + encrypted


def decrypt(aes_key, encrypted):
    iv = encrypted[:AES_BLOCK_LEN]
    payload = encrypted[AES_BLOCK_LEN:]
    return aes_cbc(aes_key, iv, payload, AES_FLAG_DECRYPT)


class E_ECDH(object):

    # Labels used to derived child keys for aes_cbc_with_ecdh_key() call
    LABEL_ORACLE_REQUEST = 'blind_oracle_request'.encode()
    LABEL_ORACLE_RESPONSE = 'blind_oracle_response'.encode()

    @classmethod
    def _generate_private_key(cls):
        counter = 4
        while counter:
            private_key = os.urandom(32)
            try:
                ec_private_key_verify(private_key)
                return private_key
            except Exception:
                counter -= 1
        raise Exception

    @classmethod
    def generate_ec_key_pair(cls):
        private_key = cls._generate_private_key()
        public_key = ec_public_key_from_private_key(private_key)
        return private_key, public_key

    def __init__(self):
        self.private_key, self.public_key = self.generate_ec_key_pair()

    def generate_shared_secrets(self, public_key):
        master_shared_key = ecdh(public_key, self.private_key)

        def _derived(val):
            return hmac_sha256(master_shared_key, bytearray([val]))

        self.request_encryption_key = _derived(0)
        self.request_hmac_key = _derived(1)
        self.response_encryption_key = _derived(2)
        self.response_hmac_key = _derived(3)

    def decrypt_with_ecdh(self, public_key, label, encrypted):
        return aes_cbc_with_ecdh_key(self.private_key, None, encrypted, public_key, label,
                                     AES_FLAG_DECRYPT)

    def encrypt_with_ecdh(self, public_key, label, plaintext):
        iv = os.urandom(AES_BLOCK_LEN)
        return aes_cbc_with_ecdh_key(self.private_key, iv, plaintext, public_key, label,
                                     AES_FLAG_ENCRYPT)
