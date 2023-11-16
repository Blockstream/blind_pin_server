import os
import time
import struct
import redis
from .lib import decrypt, encrypt
from pathlib import Path
from hmac import compare_digest
from wallycore import ec_sig_to_public_key, sha256, hmac_sha256, \
    AES_KEY_LEN_256, EC_SIGNATURE_RECOVERABLE_LEN, SHA256_LEN
from dotenv import load_dotenv

VERSION_SUPPORTED = 0
VERSION_LATEST = 1

load_dotenv()

redis_host = os.environ.get('REDIS_HOST')
redis_port = int(os.environ.get('REDIS_PORT', 6379))
redis_health_check_interval = int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 25))
redis_password = os.environ.get('REDIS_PASSWORD', None)
red_conn = redis.Redis(host=redis_host, port=redis_port, db=0, password=redis_password,
                       health_check_interval=redis_health_check_interval,
                       retry_on_timeout=True)


class FileStorage(object):

    @staticmethod
    def _get_filename(key):
        filename = '{}.pin'.format(key.hex())
        if os.path.exists('pins'):
            return Path('pins') / filename
        return filename

    @classmethod
    def get(cls, key):
        with open(cls._get_filename(key), 'rb') as f:
            return f.read()

    @classmethod
    def set(cls, key, data):
        with open(cls._get_filename(key), 'wb') as f:
            f.write(data)

    @classmethod
    def exists(cls, key):
        return os.path.exists(cls._get_filename(key))

    @classmethod
    def remove(cls, key):
        return os.remove(cls._get_filename(key))


class RedisStorage(object):

    @staticmethod
    def redis_retry(func):
        redis_sleep = int(os.environ.get('REDIS_SLEEP', 5))
        while True:
            try:
                return func()
            except redis.ConnectionError:
                print(f'Server {redis_host} unavailable, retrying in {redis_sleep}...')
                time.sleep(redis_sleep)

    @classmethod
    def get(cls, key):
        data = cls.redis_retry(lambda: red_conn.get(key))
        if not data:
            # Raise error similar to filesystem backend
            raise FileNotFoundError(2, "No record found", key.hex())
        return data

    @classmethod
    def set(cls, key, data):
        return cls.redis_retry(lambda: red_conn.set(key, data))

    @classmethod
    def exists(cls, key):
        return cls.redis_retry(lambda: red_conn.exists(key))

    @classmethod
    def remove(cls, key):
        return cls.redis_retry(lambda: red_conn.delete(key))


def get_storage():
    if not redis_host:
        print("Using filesystem based storage")
        return FileStorage

    print(f'''Connecting to {redis_host}:{redis_port},
health check every {redis_health_check_interval}''')

    RedisStorage.redis_retry(lambda: red_conn.ping())
    return RedisStorage


class PINDb(object):

    storage = get_storage()

    @classmethod
    def _extract_fields(cls, cke, data, replay_counter=None):
        assert len(data) == (2*SHA256_LEN) + EC_SIGNATURE_RECOVERABLE_LEN

        # secret + entropy + sig
        pin_secret = data[:SHA256_LEN]
        entropy = data[SHA256_LEN: SHA256_LEN + SHA256_LEN]
        sig = data[SHA256_LEN + SHA256_LEN:]

        # make sure the client_public_key signs over the replay counter too if provided
        if replay_counter is not None:
            assert len(replay_counter) == 4
            signed_msg = sha256(cke + replay_counter + pin_secret + entropy)
        else:
            signed_msg = sha256(cke + pin_secret + entropy)

        # We know mesage the signature is for, so can recover the public key
        client_public_key = ec_sig_to_public_key(signed_msg, sig)

        return pin_secret, entropy, client_public_key

    @classmethod
    def _check_v2_anti_replay(cls, server_counter, client_counter):
        # if this is v2 and the db is already upgraded we enforce the anti replay
        # ie. monotonic forward counter
        if server_counter is not None and client_counter is not None:
            server_counter = int.from_bytes(server_counter, byteorder='little', signed=False)
            client_counter = int.from_bytes(client_counter, byteorder='little', signed=False)
            assert client_counter > server_counter

    @classmethod
    def _save_pin_fields(cls, pin_pubkey_hash, hash_pin_secret, aes_key,
                         pin_pubkey, aes_pin_data_key, count, replay_counter=None):

        # the data is encrypted and then hmac'ed for authentication
        # the encrypted data can't be read by us without the user
        # sending us the pin_pubkey (we only store the hash thereof)

        storage_aes_key = hmac_sha256(aes_pin_data_key, pin_pubkey)
        count_bytes = struct.pack('B', count)
        plaintext = hash_pin_secret + aes_key + count_bytes
        version_bytes = struct.pack('B', VERSION_SUPPORTED)
        if replay_counter is not None:
            # if this is v2 we save the latest replay_counter and update the version
            plaintext += replay_counter
            version_bytes = struct.pack('B', VERSION_LATEST)
        encrypted = encrypt(storage_aes_key, plaintext)
        pin_auth_key = hmac_sha256(aes_pin_data_key, pin_pubkey_hash)

        hmac_payload = hmac_sha256(pin_auth_key, version_bytes + encrypted)

        cls.storage.set(pin_pubkey_hash, version_bytes + hmac_payload + encrypted)

        return aes_key

    @classmethod
    def _load_pin_fields(cls, pin_pubkey_hash, pin_pubkey, aes_pin_data_key):

        data = cls.storage.get(pin_pubkey_hash)
        assert len(data) == 129
        version, hmac_received, encrypted = data[:1], data[1:33], data[33:]

        # verify integrity of encrypted data first
        pin_auth_key = hmac_sha256(aes_pin_data_key, pin_pubkey_hash)
        version_bytes = struct.pack('B', VERSION_LATEST)
        len_plaintext = 32 + 32 + 1 + 4
        if version_bytes != version:
            # this is the old database, check if we are upgrading
            version_bytes = struct.pack('B', VERSION_SUPPORTED)
            len_plaintext -= 4
            assert version_bytes == version
        hmac_payload = hmac_sha256(pin_auth_key, version_bytes + encrypted)

        assert hmac_payload == hmac_received

        storage_aes_key = hmac_sha256(aes_pin_data_key, pin_pubkey)
        plaintext = decrypt(storage_aes_key, encrypted)

        assert len(plaintext) == len_plaintext, len(plaintext)

        hash_pin_secret, aes_key = plaintext[:32], plaintext[32:64]
        count = struct.unpack('B', plaintext[64: 64 + struct.calcsize('B')])[0]
        replay_counter_persisted = plaintext[65:69] if len_plaintext == 69 else None

        return hash_pin_secret, aes_key, count, replay_counter_persisted

    @classmethod
    def make_client_aes_key(cls, pin_secret, saved_key):
        # The client key returned is a combination of the aes-key persisted
        # and the raw pin_secret (that we do not persist anywhere).
        aes_key = hmac_sha256(saved_key, pin_secret)
        assert len(aes_key) == AES_KEY_LEN_256
        return aes_key

    # Get existing aes_key given pin fields
    @classmethod
    def get_aes_key_impl(cls, pin_pubkey, pin_secret, aes_pin_data_key, replay_counter=None):
        # Load the data from the pubkey
        pin_pubkey_hash = bytes(sha256(pin_pubkey))
        saved_hps, saved_key, counter, replay_local = cls._load_pin_fields(pin_pubkey_hash,
                                                                           pin_pubkey,
                                                                           aes_pin_data_key)
        # Check anti-replay counter if appropriate
        cls._check_v2_anti_replay(replay_local, replay_counter)

        # Check that the pin provided matches that saved
        hash_pin_secret = sha256(pin_secret)
        if compare_digest(saved_hps, hash_pin_secret):
            # pin-secret matches - correct pin
            # Zero the 'bad guess counter' and/or update the replay_counter
            if counter != 0 or replay_counter:
                cls._save_pin_fields(pin_pubkey_hash, saved_hps, saved_key,
                                     pin_pubkey, aes_pin_data_key, 0,
                                     replay_counter or replay_local)

            # return the saved key
            return saved_key

        # user provided wrong pin
        if counter >= 2:
            # pin failed 3 times, overwrite and then remove secret

            max_replay = 4294967295
            cls._save_pin_fields(pin_pubkey_hash,
                                 saved_hps,
                                 bytearray(AES_KEY_LEN_256),
                                 pin_pubkey,
                                 aes_pin_data_key, 3,
                                 max_replay.to_bytes(4,
                                                     byteorder='little',
                                                     signed=False))
            cls.storage.remove(pin_pubkey_hash)
            raise Exception("Too many attempts")
        else:
            # increment counter
            cls._save_pin_fields(pin_pubkey_hash, saved_hps, saved_key, pin_pubkey,
                                 aes_pin_data_key, counter + 1,
                                 replay_counter or replay_local)
            raise Exception("Invalid PIN")

    # Get existing aes_key given pin fields, or junk if pin or pubkey bad
    @classmethod
    def get_aes_key(cls, cke, payload, aes_pin_data_key, replay_counter=None):
        pin_secret, _, pin_pubkey = cls._extract_fields(cke, payload, replay_counter)

        # Translate internal exception and bad-pin into junk key
        try:
            saved_key = cls.get_aes_key_impl(pin_pubkey,
                                             pin_secret,
                                             aes_pin_data_key, replay_counter)
        except Exception as e:
            # return junk key
            saved_key = os.urandom(AES_KEY_LEN_256)

        # Combine saved key with (not persisted) pin-secret
        return cls.make_client_aes_key(pin_secret, saved_key)

    # Set pin fields, return new aes_key
    @classmethod
    def set_pin(cls, cke, payload, aes_pin_data_key, replay_counter=None):
        pin_secret, entropy, pin_pubkey = cls._extract_fields(cke, payload, replay_counter)

        # Make a new aes-key to persist from our and client entropy
        our_random = os.urandom(32)
        new_key = hmac_sha256(our_random, entropy)

        assert replay_counter is None or replay_counter == b'\x00\x00\x00\x00'

        # Persist the pin fields
        pin_pubkey_hash = bytes(sha256(pin_pubkey))
        hash_pin_secret = sha256(pin_secret)
        replay_bytes = None
        if replay_counter is not None:
            replay_init = 0
            replay_bytes = replay_init.to_bytes(4, byteorder='little', signed=False)
        saved_key = cls._save_pin_fields(pin_pubkey_hash, hash_pin_secret, new_key,
                                         pin_pubkey, aes_pin_data_key, 0, replay_bytes)

        # Combine saved key with (not persisted) pin-secret
        return cls.make_client_aes_key(pin_secret, saved_key)
