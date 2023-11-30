import unittest

import os
import json
import time
from multiprocessing import Process
from hmac import compare_digest
import requests

from ..client import PINClientECDH, PINClientECDHv2
from ..server import PINServerECDH
from ..pindb import PINDb

from ..flaskserver import app
from ..flaskserver import SESSION_LIFETIME
from wallycore import sha256, ec_sig_from_bytes, \
    AES_KEY_LEN_256, EC_FLAG_ECDSA, EC_FLAG_RECOVERABLE


class PINServerTest(unittest.TestCase):

    @staticmethod
    def new_pin_secret():
        return os.urandom(32)

    @staticmethod
    def new_entropy():
        return os.urandom(32)

    @classmethod
    def post(cls, url='', data=None):
        if data:
            userdata = json.dumps(data)
        else:
            userdata = None
        f = requests.post(cls.pinserver_url + '/' + url,
                          data=userdata)

        if f.status_code != 200:
            raise ValueError(f.status_code)

        return f.json() if url else f.text

    # Make new logical client static keys
    @classmethod
    def new_static_client_keys(cls):
        private_key, public_key = PINClientECDH.generate_ec_key_pair()

        # Cache the pinfile for this client key so we can ensure it is removed
        pinfile = bytes(sha256(public_key))
        cls.pinfiles.add(bytes(pinfile))

        # Return the keys and the pin-filename
        return private_key, public_key, pinfile

    # setUpClass() runs up the webserver
    @classmethod
    def setUpClass(cls):
        # The server public key the client would know
        with open(PINServerECDH.STATIC_SERVER_PUBLIC_KEY_FILE, 'rb') as f:
            cls.static_server_public_key = f.read()

        # pinfiles that may be created, so we can ensure they are deleted
        cls.pinfiles = set()

        # Work out the server port and localhost url
        svrport = os.getenv('PINSERVER_PORT', '5000')
        cls.pinserver_url = 'http://127.0.0.1:' + svrport

        # Start the flask server
        cls.server = Process(target=app.run, kwargs={'port': svrport})
        cls.server.start()

        # Wait for server to start
        while True:
            try:
                f = requests.get(cls.pinserver_url)
                assert f.status_code == 200
                break
            except Exception:
                pass

    # tearDownClass() shuts down the webserver and tidies up pinfiles
    @classmethod
    def tearDownClass(cls):
        # Close the web server
        cls.server.terminate()

        # Delete any pinfiles
        for f in cls.pinfiles:
            if PINDb.storage.exists(f):
                PINDb.storage.remove(f)

    # Helpers

    # Start the client/server key-exchange handshake
    def start_handshake(self, client):
        handshake = self.post('start_handshake')
        client.handshake(bytes.fromhex(handshake['ske']), bytes.fromhex(handshake['sig']))
        return client

    # Make a new ephemeral client and initialise with server handshake
    def new_client_handshake(self):
        client = PINClientECDH(self.static_server_public_key)
        return self.start_handshake(client)

    # Make a new ephemeral client and initialise with tweaked server key
    def new_client_handshakev2(self, replay_counter):
        client = PINClientECDHv2(self.static_server_public_key, replay_counter)
        return client

    # Make the server call to get/set the pin - returns the decrypted response
    def server_call(self, private_key, client, endpoint, pin_secret, entropy, replay_counter=None):
        # Make and encrypt the payload (ie. pin secret)
        ske, cke = client.get_key_exchange()
        cke_sha = cke
        if replay_counter is not None:
            assert len(replay_counter) == 4
            cke_sha = cke + replay_counter
        sig = ec_sig_from_bytes(private_key,
                                sha256(cke_sha + pin_secret + entropy),
                                EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)
        payload = pin_secret + entropy + sig

        encrypted, hmac = client.encrypt_request_payload(payload)

        # Make call and parse response
        urldata = {'ske': ske.hex(),
                   'cke': cke.hex(),
                   'encrypted_data': encrypted.hex(),
                   'hmac_encrypted_data': hmac.hex()}
        if replay_counter:
            urldata['replay_counter'] = replay_counter.hex()
            del urldata['ske']
        response = self.post(endpoint, urldata)
        encrypted = bytes.fromhex(response['encrypted_key'])
        hmac = bytes.fromhex(response['hmac'])

        # Return decrypted payload
        return client.decrypt_response_payload(encrypted, hmac)

    def get_pin(self, private_key, pin_secret, entropy):
        # Create new ephemeral client, initiate handshake, and make call
        client = self.new_client_handshake()
        return self.server_call(
            private_key, client, 'get_pin', pin_secret, entropy)

    def set_pin(self, private_key, pin_secret, entropy):
        # Create new ephemeral client, initiate handshake, and make call
        client = self.new_client_handshake()
        return self.server_call(
            private_key, client, 'set_pin', pin_secret, entropy)

    def get_pinv2(self, private_key, pin_secret, entropy, replay_counter):
        # Create new ephemeral client, initiate handshake, and make call
        client = self.new_client_handshakev2(replay_counter)
        return self.server_call(
            private_key, client, 'get_pin', pin_secret, entropy, replay_counter)

    def set_pinv2(self, private_key, pin_secret, entropy, replay_counter):
        # Create new ephemeral client, initiate handshake, and make call
        client = self.new_client_handshakev2(replay_counter)
        return self.server_call(
            private_key, client, 'set_pin', pin_secret, entropy, replay_counter)

    # Tests
    def test_get_index(self):
        # No index or similar
        for path in ['index.htm', 'index.html', 'public/']:
            f = requests.get(self.pinserver_url + '/' + path)
            self.assertEqual(f.status_code, 404)

            f = requests.post(self.pinserver_url + '/' + path)
            self.assertEqual(f.status_code, 404)

    def test_get_root_empty(self):
        # Root is an empty document
        f = requests.get(self.pinserver_url)
        self.assertEqual(f.status_code, 200)
        self.assertFalse(f.text)

        # But get 405 if we try to POST
        f = requests.post(self.pinserver_url)
        self.assertEqual(f.status_code, 405)

    def test_set_and_get_pin(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret = self.new_pin_secret()

        # Make a new client and set the pin secret to get a new aes key
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy())
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        # Get key with a new client, with the correct pin secret (new entropy)
        for attempt in range(5):
            aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy())
            self.assertTrue(compare_digest(aeskey_g, aeskey_s))

    def test_bad_guesses_clears_pin(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, pinfile = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Set and verify the pin - ensure underlying file created
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = self.set_pin(priv_key, pin_secret, entropy)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        aeskey_g = self.get_pin(priv_key, pin_secret, entropy)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Bad guesses at PIN
        for attempt in range(3):
            # Attempt to get with bad pin
            bad_secret = os.urandom(32)
            guesskey = self.get_pin(priv_key, bad_secret, entropy)

            # Wrong pin should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after three failed attempts server deletes the file
        self.assertFalse(PINDb.storage.exists(pinfile))

        # Now even the correct pin will fail...
        aeskey = self.get_pin(priv_key, bad_secret, entropy)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertFalse(compare_digest(aeskey, aeskey_s))
        self.assertFalse(PINDb.storage.exists(pinfile))

    def test_bad_pubkey_breaks(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, pinfile = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Set and verify the pin - ensure underlying file created
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = self.set_pin(priv_key, pin_secret, entropy)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        aeskey_g = self.get_pin(priv_key, pin_secret, entropy)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Bad attempts with bad pub_key
        for attempt in range(3):
            # Attempt to get with bad pub_key
            bad_key = os.urandom(32)
            guesskey = self.get_pin(bad_key, pin_secret, entropy)

            # Wrong pin should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after three failed attempts server does nothing
        self.assertTrue(PINDb.storage.exists(pinfile))

        # The correct pin will continue to work
        aeskey = self.get_pin(priv_key, pin_secret, entropy)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertTrue(compare_digest(aeskey, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_two_users_with_same_pin(self):
        # Two users
        clientA_private_key, _, _ = self.new_static_client_keys()
        clientB_private_key, _, _ = self.new_static_client_keys()

        # pin plus its salt/iv/entropy
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # A and B use the same values... bizarre but should be fine
        aeskey_sA = self.set_pin(clientA_private_key, pin_secret, entropy)
        aeskey_sB = self.set_pin(clientB_private_key, pin_secret, entropy)
        self.assertFalse(compare_digest(aeskey_sA, aeskey_sB))

        aeskey_gA = self.get_pin(clientA_private_key, pin_secret, entropy)
        self.assertTrue(compare_digest(aeskey_gA, aeskey_sA))

        aeskey_gB = self.get_pin(clientB_private_key, pin_secret, entropy)
        self.assertTrue(compare_digest(aeskey_gB, aeskey_sB))

        self.assertFalse(compare_digest(aeskey_gA, aeskey_gB))

    def test_rejects_on_bad_json(self):
        # Create new ephemeral client, initiate handshake, and make call
        client = self.new_client_handshake()
        ske, cke = client.get_key_exchange()

        # Make call with bad/missing parameters
        urldata = {'ske': ske.hex(),
                   'cke': cke.hex(),
                   # 'encrypted_data' missing
                   'hmac_encrypted_data': 'abc123'}

        with self.assertRaises(ValueError) as cm:
            self.post('get_pin', urldata)

        # Make call with not-even-json
        urldata = 'This is not even json'
        with self.assertRaises(ValueError) as cm:
            self.post('get_pin', urldata)

    def test_rejects_without_client_entropy(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin but no salt/iv/entropy
        pin_secret, entropy = self.new_pin_secret(), bytearray()

        # Make a new client and set the pin secret to get a new aes key
        with self.assertRaises(ValueError) as cm:
            self.set_pin(priv_key, pin_secret, entropy)

        self.assertEqual('500', str(cm.exception.args[0]))

        with self.assertRaises(ValueError) as cm:
            self.get_pin(priv_key, pin_secret, entropy)

        self.assertEqual('500', str(cm.exception.args[0]))

    def test_delayed_interaction(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin plus its salt/iv/entropy
        pin_secret = self.new_pin_secret()

        # Set and verify the pin
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy())
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy())
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # If we delay in the server interaction it will fail with a 500 error
        client = self.new_client_handshake()
        time.sleep(SESSION_LIFETIME + 1)  # Sufficiently long delay

        with self.assertRaises(ValueError) as cm:
            self.server_call(priv_key, client, 'get_pin', pin_secret,
                             self.new_entropy())

        self.assertEqual('500', str(cm.exception.args[0]))

    def test_cannot_reuse_client_session(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin plus its salt/iv/entropy
        pin_secret = self.new_pin_secret()

        # Set pin
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy())

        # Get/verify pin with a new client
        client = self.new_client_handshake()
        aeskey_g = self.server_call(priv_key, client, 'get_pin', pin_secret,
                                    self.new_entropy())
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Trying to reuse the session should fail with a 500 error
        with self.assertRaises(ValueError) as cm:
            self.server_call(priv_key, client, 'get_pin', pin_secret,
                             self.new_entropy())

        self.assertEqual('500', str(cm.exception.args[0]))

        # Not great, but we could reuse the client if we re-initiate handshake
        # (But that would use same cke which is not ideal.)
        self.start_handshake(client)
        aeskey = self.server_call(priv_key, client, 'get_pin', pin_secret,
                                  self.new_entropy())
        self.assertTrue(compare_digest(aeskey, aeskey_s))

    def test_v2_happypath_with_simulated_replay(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret = self.new_pin_secret()

        # assert you can't set pin with a replay_counter different than 0
        with self.assertRaises(ValueError) as cm:
            replay_counter = 1
            self.set_pinv2(priv_key, pin_secret, self.new_entropy(),
                           replay_counter.to_bytes(4,
                                                   byteorder='little',
                                                   signed=False))

        # set the pin secret to get a new aes key
        replay_counter = 0
        aeskey_s = self.set_pinv2(priv_key, pin_secret, self.new_entropy(),
                                  replay_counter.to_bytes(4, byteorder='little',
                                  signed=False))

        # retrieve the key again with our correct pin secret
        replay_counter = 1
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                signed=False))

        # Now let's compare
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        for i in range(5):
            # Simulate a reply attempt failing N times, it doesn't affect pin
            # attempts / dos
            aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                    replay_counter.to_bytes(4,
                                                            byteorder='little',
                                                            signed=False))
            self.assertFalse(compare_digest(aeskey, aeskey_s))

        # retrieve the key again using v1
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy())
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Incrementing the counter monotonically works again
        replay_counter = 2
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                                        signed=False))
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        # Incrementing the counter monotonically works even in case of network
        # errors where some request is missed
        replay_counter = 4
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                                        signed=False))
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        bad_secret = self.new_pin_secret()
        for i in range(3):
            # exaust pin attmempts with good replay_counter
            replay_counter = i + 5
            replay_counter = replay_counter.to_bytes(4, byteorder='little', signed=False)
            aeskey = self.get_pinv2(priv_key, bad_secret, self.new_entropy(), replay_counter)
            self.assertFalse(compare_digest(aeskey, aeskey_s))

        # retrieve the key again using v1 should fail
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy())
        self.assertFalse(compare_digest(aeskey_g, aeskey_s))

        # Incrementing the counter monotonically also fails
        replay_counter = 8
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                                        signed=False))
        self.assertFalse(compare_digest(aeskey, aeskey_s))

    def test_v2_happypath_with_simulated_replay_upgrade(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret = self.new_pin_secret()

        # Make a new client and set the pin secret to get a new aes key
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy())
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        # retrieve the key again with our correct pin secret
        replay_counter = 0
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                signed=False))

        # Now let's compare
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        for i in range(5):
            # Simulate a reply attempt failing N times, it doesn't affect pin
            # attempts / dos
            aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                    replay_counter.to_bytes(4,
                                                            byteorder='little',
                                                            signed=False))
            self.assertFalse(compare_digest(aeskey, aeskey_s))

        # retrieve the key again using v1
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy())
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Incrementing the counter monotonically works again
        replay_counter = 2
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                                        signed=False))
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        # Incrementing the counter monotonically works even in case of network
        # errors where some request is missed
        replay_counter = 4
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                                        signed=False))
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        bad_secret = self.new_pin_secret()
        for i in range(3):
            # exaust pin attmempts with good replay_counter
            aeskey = self.get_pin(priv_key, bad_secret, self.new_entropy())
            self.assertFalse(compare_digest(aeskey, aeskey_s))

        # retrieve the key again using v1 should fail
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy())
        self.assertFalse(compare_digest(aeskey_g, aeskey_s))

        # Incrementing the counter monotonically also fails
        replay_counter = 5
        aeskey = self.get_pinv2(priv_key, pin_secret, self.new_entropy(),
                                replay_counter.to_bytes(4, byteorder='little',
                                                        signed=False))
        self.assertFalse(compare_digest(aeskey, aeskey_s))


if __name__ == '__main__':
    unittest.main()
