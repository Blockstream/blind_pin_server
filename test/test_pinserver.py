import unittest

import os
import json
import base64
import time
from multiprocessing import Process
from hmac import compare_digest
import requests

from ..client import PINClientECDH, PINClientECDHv1, PINClientECDHv2
from ..server import PINServerECDH
from ..pindb import PINDb

from ..flaskserver import app
from ..flaskserver import SESSION_LIFETIME
from wallycore import sha256, ec_sig_from_bytes, \
    AES_KEY_LEN_256, EC_FLAG_ECDSA, EC_FLAG_RECOVERABLE


class PINServerTest(unittest.TestCase):
    # Protocol v2 client replay coutner
    v2_client_counter = 13  # arbitrary initial value

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
    def start_handshake_v1(self, client):
        assert isinstance(client, PINClientECDHv1)
        handshake = self.post('start_handshake')
        client.handshake(bytes.fromhex(handshake['ske']), bytes.fromhex(handshake['sig']))
        return client

    # Make a new ephemeral client and initialise with server handshake
    def new_client_v1(self):
        client = PINClientECDHv1(self.static_server_public_key)
        return self.start_handshake_v1(client)

    def new_client_v2(self, reset_replay_counter=False):
        if reset_replay_counter:
            client_counter = b'\x00\x00\x00\x00'
        else:
            self.v2_client_counter += 1  # increment - may be unnecessary but ensures monotonic
            client_counter = self.v2_client_counter.to_bytes(4, byteorder='little', signed=False)

        return PINClientECDHv2(self.static_server_public_key, client_counter)

    # Make the server call to get/set the pin - returns the decrypted response
    # NOTE: explicit hmac fields
    def server_call_v1(self, private_key, client, endpoint, pin_secret, entropy,
                       fn_perturb_request=None):
        assert isinstance(client, PINClientECDHv1)

        # Make and encrypt the payload (ie. pin secret)
        ske, cke = client.get_key_exchange()
        sig = ec_sig_from_bytes(private_key,
                                sha256(cke + pin_secret + entropy),
                                EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)
        payload = pin_secret + entropy + sig

        encrypted, hmac = client.encrypt_request_payload(payload)

        # Make call and parse response
        # Includes 'ske' and 'hmac', but no 'replay_counter'
        urldata = {'ske': ske.hex(),
                   'cke': cke.hex(),
                   'encrypted_data': encrypted.hex(),
                   'hmac_encrypted_data': hmac.hex()}

        # Caller can mangle data before it is sent
        if fn_perturb_request:
            urldata = fn_perturb_request(urldata)

        response = self.post(endpoint, urldata)
        encrypted = bytes.fromhex(response['encrypted_key'])
        hmac = bytes.fromhex(response['hmac'])

        # Return decrypted payload
        return client.decrypt_response_payload(encrypted, hmac)

    # Make the server call to get/set the pin - returns the decrypted response
    # NOTE: signature covers replay counter
    # NOTE: implicit hmac
    # NOTE: all fields concatenated into one, and ascii85 encoded
    def server_call_v2(self, private_key, client, endpoint, pin_secret, entropy,
                       fn_perturb_request=None):
        assert isinstance(client, PINClientECDHv2)

        # Make and encrypt the payload (ie. pin secret)
        ske, cke = client.get_key_exchange()
        sig = ec_sig_from_bytes(private_key,
                                sha256(cke + client.replay_counter + pin_secret + entropy),
                                EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)
        payload = pin_secret + entropy + sig

        encrypted = client.encrypt_request_payload(payload)

        # Make call and parse response
        # NOTE: we temporarily use the v1-like hex struct for the test perturbation
        # function (ie. to mess with the data before posting)
        # Includes 'replay_counter' but not 'ske' or 'hmac'
        urldata = {'cke': cke.hex(),
                   'encrypted_data': encrypted.hex(),
                   'replay_counter': client.replay_counter.hex()}

        # Caller can mangle data before it is sent
        if fn_perturb_request:
            urldata = fn_perturb_request(urldata)

        # v2 concatenates all the fields into one and uses ascii85-encoding
        cke = bytes.fromhex(urldata.get('cke', ''))
        replay_counter = bytes.fromhex(urldata.get('replay_counter', ''))
        encrypted = bytes.fromhex(urldata.get('encrypted_data', ''))
        payload = cke + replay_counter + encrypted
        data = base64.a85encode(payload).decode()
        urldata = {'data': data}

        response = self.post(endpoint, urldata)
        encrypted = base64.a85decode(response['data'].encode())

        # Return decrypted payload
        return client.decrypt_response_payload(encrypted)

    def make_server_call(self, private_key, endpoint, pin_secret, entropy, use_v2_protocol,
                         fn_perturb_request=None):
        if use_v2_protocol:
            client = self.new_client_v2()
            server_call = self.server_call_v2
        else:
            client = self.new_client_v1()
            server_call = self.server_call_v1

        return server_call(private_key, client, endpoint, pin_secret, entropy, fn_perturb_request)

    def get_pin(self, private_key, pin_secret, entropy, use_v2_protocol):
        return self.make_server_call(private_key, 'get_pin', pin_secret, entropy, use_v2_protocol)

    def set_pin(self, private_key, pin_secret, entropy, use_v2_protocol):
        return self.make_server_call(private_key, 'set_pin', pin_secret, entropy, use_v2_protocol)

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

    def _test_set_and_get_pin_impl(self, use_v2_protocol):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret = self.new_pin_secret()

        # Make a new client and set the pin secret to get a new aes key
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        # Get key with a new client, with the correct pin secret (with or without entropy)
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

    def test_set_and_get_pin(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_set_and_get_pin_impl(use_v2_protocol)

    def _test_protocol_upgrade_downgrade_impl(self, v2set, v2get):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret = self.new_pin_secret()

        # Make a new client and set the pin secret to get a new aes key
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), v2set)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        # Now client changes protocol version - should all work seamlessly
        # upgrade, and downgrade ...
        # Get key with a new client, with the correct pin secret (new entropy)
        aeskey = self.get_pin(priv_key, pin_secret, self.new_entropy(), v2get)
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        aeskey = self.get_pin(priv_key, pin_secret, self.new_entropy(), not v2get)
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        aeskey = self.get_pin(priv_key, pin_secret, b'', v2get)
        self.assertTrue(compare_digest(aeskey, aeskey_s))

        aeskey = self.get_pin(priv_key, pin_secret, b'', not v2get)
        self.assertTrue(compare_digest(aeskey, aeskey_s))

    def test_protocol_upgrade_downgrade(self):
        for v2set, v2get in [(False, False), (False, True), (True, False), (True, True)]:
            with self.subTest(set='v2' if v2set else 'v1', get='v2' if v2get else 'v1'):
                self._test_protocol_upgrade_downgrade_impl(v2set, v2get)

    def _test_bad_guesses_clears_pin_impl(self, use_v2_protocol):
        # Make ourselves a static key pair for this logical client
        priv_key, _, pinfile = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Set and verify the pin - ensure underlying file created
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = self.set_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        aeskey_g = self.get_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Get does not need client entropy
        entropy = b''
        aeskey_g = self.get_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Bad guesses at PIN
        for attempt in range(3):
            # Attempt to get with bad pin
            bad_secret = os.urandom(32)
            guesskey = self.get_pin(priv_key, bad_secret, entropy, use_v2_protocol)

            # Wrong pin should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after three failed attempts server deletes the file
        self.assertFalse(PINDb.storage.exists(pinfile))

        # Now even the correct pin will fail...
        aeskey = self.get_pin(priv_key, bad_secret, entropy, use_v2_protocol)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertFalse(compare_digest(aeskey, aeskey_s))
        self.assertFalse(PINDb.storage.exists(pinfile))

    def test_bad_guesses_clears_pin(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_bad_guesses_clears_pin_impl(use_v2_protocol)

    def _test_bad_pubkey_breaks_impl(self, use_v2_protocol):
        # Make ourselves a static key pair for this logical client
        priv_key, _, pinfile = self.new_static_client_keys()

        # The 'correct' client pin
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Set and verify the pin - ensure underlying file created
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = self.set_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        aeskey_g = self.get_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Get does not need client entropy
        entropy = b''
        aeskey_g = self.get_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Bad attempts with bad pub_key
        for attempt in range(3):
            # Attempt to get with bad pub_key
            bad_key = os.urandom(32)
            guesskey = self.get_pin(bad_key, pin_secret, entropy, use_v2_protocol)

            # Wrong pin should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after three failed attempts server does nothing
        self.assertTrue(PINDb.storage.exists(pinfile))

        # The correct pin will continue to work
        aeskey = self.get_pin(priv_key, pin_secret, entropy, use_v2_protocol)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertTrue(compare_digest(aeskey, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_bad_pubkey_breaks(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_bad_pubkey_breaks_impl(use_v2_protocol)

    def _test_two_users_with_same_pin_impl(self, v2X, v2Y):
        # Two users
        clientX_private_key, _, _ = self.new_static_client_keys()
        clientY_private_key, _, _ = self.new_static_client_keys()

        # pin plus its salt/iv/entropy
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # X and Y use the same values... bizarre but should be fine
        aeskey_sX = self.set_pin(clientX_private_key, pin_secret, entropy, v2X)
        aeskey_sY = self.set_pin(clientY_private_key, pin_secret, entropy, v2Y)
        self.assertFalse(compare_digest(aeskey_sX, aeskey_sY))

        # Get does not need client entropy
        entropy = b''
        aeskey_gX = self.get_pin(clientX_private_key, pin_secret, entropy, v2X)
        self.assertTrue(compare_digest(aeskey_gX, aeskey_sX))

        aeskey_gY = self.get_pin(clientY_private_key, pin_secret, entropy, v2Y)
        self.assertTrue(compare_digest(aeskey_gY, aeskey_sY))

        self.assertFalse(compare_digest(aeskey_gX, aeskey_gY))

    def test_two_users_with_same_pin(self):
        for v2X, v2Y in [(False, False), (False, True), (True, True)]:
            with self.subTest(X='v2' if v2X else 'v1', Y='v2' if v2Y else 'v1'):
                self._test_two_users_with_same_pin_impl(v2X, v2Y)

    def test_rejects_bad_payload_not_json(self):
        # Make call with not-even-json
        urldata = 'This is not even json'

        with self.assertRaises(ValueError) as cm:
            self.post('set_pin', urldata)
        self.assertEqual('500', str(cm.exception.args[0]))

        with self.assertRaises(ValueError) as cm:
            self.post('get_pin', urldata)
        self.assertEqual('500', str(cm.exception.args[0]))

    def _test_rejects_on_bad_json_impl(self, use_v2_protocol):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Various ways to mangle the json request payload
        bad_ske, bad_cke = self.new_client_v1().get_key_exchange()

        def _short(field):
            def _fn(d):
                d[field] = d[field][:-2]
                return d
            return _fn

        def _long(field):
            def _fn(d):
                d[field] = d[field] + 'ff'
                return d
            return _fn

        def _random(field):
            def _fn(d):
                d[field] = os.urandom(len(bytes.fromhex(d[field]))).hex()
                return d
            return _fn

        def _set(field, value):
            def _fn(d):
                d[field] = value
                return d
            return _fn

        def _remove(field):
            def _fn(d):
                del d[field]
                return d
            return _fn

        request_manglers = [_set('cke', bad_cke.hex())]
        request_manglers.extend(f('cke') for f in [_short, _long, _remove])
        request_manglers.extend(f('encrypted_data') for f in [_random, _short, _long, _remove])

        if use_v2_protocol:
            request_manglers.extend(f('replay_counter') for f in [_random, _short, _long, _remove])
        else:
            request_manglers.append(_set('ske', bad_ske.hex()))
            request_manglers.extend(f('ske') for f in [_short, _long, _remove])
            request_manglers.extend(f('hmac_encrypted_data')
                                    for f in [_random, _short, _long, _remove])

        for mangler in request_manglers:
            for endpoint in ['get_pin', 'set_pin']:
                with self.assertRaises(ValueError) as cm:
                    self.make_server_call(priv_key, endpoint, pin_secret, self.new_entropy(),
                                          use_v2_protocol, mangler)

                self.assertEqual('500', str(cm.exception.args[0]))

    def test_rejects_on_bad_json(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_rejects_on_bad_json_impl(use_v2_protocol)

    def _test_client_entropy_impl(self, use_v2_protocol):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()
        pin_secret = self.new_pin_secret()

        # Fails if setting the pin secret without passing client entropy
        with self.assertRaises(ValueError) as cm:
            self.set_pin(priv_key, pin_secret, b'', use_v2_protocol)

        self.assertEqual('500', str(cm.exception.args[0]))

        # Set pin with client entropy - fine
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol=False)

        # Get call works with or without entropy (it's ignored in any case)
        aeskey_g = self.get_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', use_v2_protocol)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        self.assertEqual('500', str(cm.exception.args[0]))

    def test_client_entropy(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_client_entropy_impl(use_v2_protocol)

    def test_delayed_interaction_v1(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin plus its salt/iv/entropy
        pin_secret = self.new_pin_secret()

        # Set and verify the pin
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol=False)
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', use_v2_protocol=False)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # If we delay in the server interaction it will fail with a 500 error
        client = self.new_client_v1()
        time.sleep(SESSION_LIFETIME + 1)  # Sufficiently long delay

        with self.assertRaises(ValueError) as cm:
            self.server_call_v1(priv_key, client, 'get_pin', pin_secret, b'')

        self.assertEqual('500', str(cm.exception.args[0]))

    def test_cannot_reuse_client_session_v1(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin plus its salt/iv/entropy
        pin_secret = self.new_pin_secret()

        # Set pin
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol=False)

        # Get/verify pin with a new client
        client = self.new_client_v1()
        aeskey_g = self.server_call_v1(priv_key, client, 'get_pin', pin_secret,
                                       self.new_entropy())
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Trying to reuse the session should fail with a 500 error
        # because the server has closed that ephemeral encryption session
        with self.assertRaises(ValueError) as cm:
            self.server_call_v1(priv_key, client, 'get_pin', pin_secret, b'')

        self.assertEqual('500', str(cm.exception.args[0]))

        # Not great, but we could reuse the client if we re-initiate handshake
        # (But that would use same cke which is not ideal/recommended.)
        self.start_handshake_v1(client)
        aeskey = self.server_call_v1(priv_key, client, 'get_pin', pin_secret, b'')
        self.assertTrue(compare_digest(aeskey, aeskey_s))

    def test_cannot_reuse_client_session_v2(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin plus its salt/iv/entropy
        pin_secret = self.new_pin_secret()

        # Set pin
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol=True)

        # Get/verify pin with a new client
        client = self.new_client_v2(False)
        aeskey_g = self.server_call_v2(priv_key, client, 'get_pin', pin_secret, b'')
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Trying to reuse the session should appear to work, but will return a junk key
        # (ie. same as bad pin) because the server-side 'replay counter' has moved on
        aeskey = self.server_call_v2(priv_key, client, 'get_pin', pin_secret, b'')
        self.assertFalse(compare_digest(aeskey, aeskey_s))

        # Set-pin should fail more overtly (NOTE: needs client entropy passed)
        with self.assertRaises(ValueError) as cm:
            aeskey_g = self.server_call_v2(priv_key, client, 'set_pin', self.new_pin_secret(),
                                           self.new_entropy())
        self.assertEqual('500', str(cm.exception.args[0]))

    def test_set_pin_counter_v2(self):
        # Make ourselves a static key pair for this logical client
        priv_key, _, _ = self.new_static_client_keys()

        # The 'correct' client pin plus its salt/iv/entropy
        pin_secret = self.new_pin_secret()

        # Set pin
        aeskey_s = self.set_pin(priv_key, pin_secret, self.new_entropy(), use_v2_protocol=True)

        # Get/verify pin with a new client
        client = self.new_client_v2()
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', use_v2_protocol=True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Trying to set-pin with same counter should fail
        with self.assertRaises(ValueError) as cm:
            aeskey_g = self.server_call_v2(priv_key, client, 'set_pin', self.new_pin_secret(),
                                           self.new_entropy())
        self.assertEqual('500', str(cm.exception.args[0]))

        # Trying to set-pin with zero counter should fail
        client = self.new_client_v2(True)
        with self.assertRaises(ValueError) as cm:
            aeskey_g = self.server_call_v2(priv_key, client, 'set_pin', self.new_pin_secret(),
                                           self.new_entropy())
        self.assertEqual('500', str(cm.exception.args[0]))

        # Existing saved PIN undamaged as set attempt failed
        aeskey_g = self.get_pin(priv_key, pin_secret, b'', use_v2_protocol=True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Trying to set pin while respecting the counter should work
        pin_secret = self.new_pin_secret()
        client = self.new_client_v2()
        aeskey_s = self.server_call_v2(priv_key, client, 'set_pin', pin_secret, self.new_entropy())
        self.assertFalse(compare_digest(aeskey_g, aeskey_s))  # changed

        aeskey_g = self.get_pin(priv_key, pin_secret, b'', use_v2_protocol=True)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))


if __name__ == '__main__':
    unittest.main()
