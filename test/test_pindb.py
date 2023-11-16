import unittest

import os
from hmac import compare_digest

from ..pindb import PINDb
from ..lib import E_ECDH

from wallycore import sha256, ec_sig_from_bytes, \
    AES_KEY_LEN_256, EC_FLAG_ECDSA, EC_FLAG_RECOVERABLE


# Tests the pindb and payload handling without any reference to the ecdh
# protocol/encryption wrapper.
class PINDbTest(unittest.TestCase):

    @staticmethod
    def new_pin_secret():
        return os.urandom(32)

    @staticmethod
    def new_entropy():
        return os.urandom(32)

    @staticmethod
    def make_payload(signing_key, cke, secret_in, entropy_in, v2_replay_counter=None):
        # Build the expected payload - if the v2_replay_counter is passed, assume protocol v2
        # and include that counter in the data being signed.  Otherwise assume v1 and ignore.
        counter = v2_replay_counter if v2_replay_counter else b''
        sig = ec_sig_from_bytes(signing_key,
                                sha256(cke + counter + secret_in + entropy_in),
                                EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)

        return secret_in + entropy_in + sig

    @classmethod
    def new_keys(cls):
        # USE ECDH class just because it's convenient way to make key pairs
        privkey, pubkey = E_ECDH.generate_ec_key_pair()
        _, cke = E_ECDH.generate_ec_key_pair()

        # add the pin_pubkey_hash to the set
        pin_pubkey_hash = bytes(sha256(pubkey))
        cls.pinfiles.add(pin_pubkey_hash)

        return privkey, pubkey, cke, pin_pubkey_hash

    @classmethod
    def setUpClass(cls):
        # pinfiles that may be created, so we can ensure they are deleted
        cls.pinfiles = set()

    # tearDownClass() tidies up any remaining pinfiles
    @classmethod
    def tearDownClass(cls):
        # Delete any remaining pinfiles
        for f in cls.pinfiles:
            if PINDb.storage.exists(f):
                PINDb.storage.remove(f)

    def _test_extract_fields_impl(self, v2_replay_counter):
        # Reinitialise keys and secret and entropy
        privkey, pubkey, cke, _ = self.new_keys()
        secret_in, entropy_in = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload
        payload = self.make_payload(privkey, cke, secret_in, entropy_in, v2_replay_counter)

        # Check pindb function can extract the components from the payload
        secret_out, entropy_out, pubkey_out = PINDb._extract_fields(cke, payload, v2_replay_counter)
        self.assertEqual(secret_out, secret_in)
        self.assertEqual(entropy_out, entropy_in)

        # Check the public key is correctly recovered from the signature
        self.assertEqual(pubkey_out, pubkey)

    def test_extract_fields(self):
        for v2_replay_counter in [None, os.urandom(4), os.urandom(4)]:
            with self.subTest(protocol='v2' if v2_replay_counter else 'v1'):
                self._test_extract_fields_impl(v2_replay_counter)

    def _test_mismatching_sig_impl(self, v2_replay_counter):
        # Get two sets of keys and a new secret
        privX, pubX, ckeX, _ = self.new_keys()
        privY, pubY, ckeY, _ = self.new_keys()
        secret_in, entropy_in = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload
        payload = self.make_payload(privX, ckeX, secret_in, entropy_in, v2_replay_counter)

        # Call the pindb function to extract the components from the payload
        secret_out, entropy_out, pubkey = PINDb._extract_fields(ckeX, payload, v2_replay_counter)
        self.assertEqual(secret_out, secret_in)
        self.assertEqual(entropy_out, entropy_in)
        self.assertEqual(pubkey, pubX)

        # Call the pindb function to extract the components from the payload
        # but use a mismatched cke - the sig should not yield either pubkey.
        secret_out, entropy_out, pubkey = PINDb._extract_fields(ckeY, payload, v2_replay_counter)
        self.assertEqual(secret_out, secret_in)
        self.assertEqual(entropy_out, entropy_in)
        self.assertNotEqual(pubkey, pubX)
        self.assertNotEqual(pubkey, pubY)

        # Call the pindb function again with the correct cke, but pass a bad replay counter
        for bad_counter in [os.urandom(4), None if v2_replay_counter else os.urandom(4)]:
            secret_out, entropy_out, pubkey = PINDb._extract_fields(ckeX, payload, bad_counter)
            self.assertEqual(secret_out, secret_in)
            self.assertEqual(entropy_out, entropy_in)
            self.assertNotEqual(pubkey, pubX)
            self.assertNotEqual(pubkey, pubY)

    def test_mismatching_sig(self):
        for v2_replay_counter in [None, os.urandom(4), os.urandom(4)]:
            with self.subTest(protocol='v2' if v2_replay_counter else 'v1'):
                self._test_mismatching_sig_impl(v2_replay_counter)

    def test_load_nonexistent_file_throws(self):
        # Trying to read non-existent file throws (and does not create file)
        _, _, _, pinfile = self.new_keys()
        self.assertFalse(PINDb.storage.exists(pinfile))
        with self.assertRaises((FileNotFoundError, Exception)) as _:
            PINDb._load_pin_fields(pinfile, None, None)
        self.assertFalse(PINDb.storage.exists(pinfile))

    def _test_save_and_load_pin_fields_impl(self, use_v2_protocol):
        # Reinitialise keys and secret
        _, _, _, pinfile = self.new_keys()
        pin_secret, key_in = self.new_pin_secret(), self.new_entropy()
        hps_in = sha256(pin_secret)
        count_in = 5

        user_id = os.urandom(32)
        aes_pin = bytes(os.urandom(32))

        # Save some data - check new file created
        v2_replay_counter = b'\x00\x00\x00\x00' if use_v2_protocol else None
        new_key = PINDb._save_pin_fields(pinfile, hps_in, key_in, user_id, aes_pin,
                                         count_in, v2_replay_counter)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Atm the 'new key' returned should be the one passed in
        self.assertEqual(new_key, key_in)

        # Read file back in - ensure fields the same
        v2_prior_counter = v2_replay_counter
        v2_replay_counter = b'\x01\x00\x00\x00' if use_v2_protocol else None
        hps_out, key_out, count_out, replay_local = PINDb._load_pin_fields(pinfile,
                                                                           user_id,
                                                                           aes_pin)
        self.assertEqual(hps_out, hps_in)
        self.assertEqual(key_out, key_in)
        self.assertEqual(count_out, count_in)
        self.assertEqual(replay_local, v2_prior_counter)

        # Ensure we can set zero the count of an existing file
        count_in = 0
        v2_prior_counter = v2_replay_counter
        v2_replay_counter = b'\x05\x00\x00\x00' if use_v2_protocol else None
        new_key = PINDb._save_pin_fields(pinfile, hps_in, key_in, user_id, aes_pin,
                                         count_in, v2_replay_counter)

        v2_prior_counter = v2_replay_counter
        v2_replay_counter = b'\xc2\x00\x00\x00' if use_v2_protocol else None
        hps_out, key_out, count_out, replay_local = PINDb._load_pin_fields(pinfile,
                                                                           user_id,
                                                                           aes_pin)
        self.assertEqual(hps_out, hps_in)
        self.assertEqual(key_out, key_in)
        self.assertEqual(count_out, count_in)
        self.assertEqual(replay_local, v2_prior_counter)

        # Ensure we can't decrypt the pin with the wrong aes_key, hmac won't match
        bad_aes = os.urandom(32)
        with self.assertRaises(AssertionError) as _:
            PINDb._load_pin_fields(pinfile, user_id, bad_aes)

    def test_save_and_load_pin_fields(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_save_and_load_pin_fields_impl(use_v2_protocol)

    def _test_set_and_get_pin_impl(self, v2set, v2get):
        # Reinitialise keys and secret
        privkey, _, cke, pinfile = self.new_keys()
        pin_secret = self.new_pin_secret()
        pin_aes_key = bytes(os.urandom(32))

        # Set the pin - check this creates the file
        v2_replay_counter = b'\x00\x00\x00\x00' if v2set else None
        payload = self.make_payload(privkey, cke, pin_secret, self.new_entropy(), v2_replay_counter)
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Get the key with the pin - new payload has new entropy (same pin)
        v2_replay_counter = os.urandom(4) if v2get else None
        payload = self.make_payload(privkey, cke, pin_secret, self.new_entropy(), v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_set_and_get_pin(self):
        for v2set, v2get in [(False, False), (False, True), (True, False), (True, True)]:
            with self.subTest(set='v2' if v2set else 'v1', get='v2' if v2get else 'v1'):
                for i in range(3):
                    self._test_set_and_get_pin_impl(v2set, v2get)

    def _test_bad_guesses_clears_pin_impl(self, v2set, v2get):
        # Reinitialise keys and secret
        privkey, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload
        v2_replay_counter = b'\x00\x00\x00\x00' if v2set else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)

        # Set and verify the the pin - check this creates the file
        self.assertFalse(PINDb.storage.exists(pinfile))
        pin_aes_key = bytes(os.urandom(32))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        v2_replay_counter = b'\x01\x00\x00\x00' if v2set else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Bad guesses at PIN
        for attempt in range(3):
            # Attempt to get with bad pin (using same entropy)
            v2_replay_counter = (10 + attempt).to_bytes(4, 'little') if v2get else None
            bad_secret = os.urandom(32)
            bad_payload = self.make_payload(privkey, cke, bad_secret, entropy, v2_replay_counter)
            guesskey = PINDb.get_aes_key(cke, bad_payload, pin_aes_key, v2_replay_counter)

            # Wrong pin should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after three failed attempts server deletes the file
        self.assertFalse(PINDb.storage.exists(pinfile))

        # Now even the correct pin will fail...
        v2_replay_counter = b'\x0c\x20\x00\x00' if v2get else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertFalse(compare_digest(aeskey, aeskey_s))
        self.assertFalse(PINDb.storage.exists(pinfile))

    def test_bad_guesses_clears_pin(self):
        for v2set, v2get in [(False, False), (False, True), (True, False), (True, True)]:
            with self.subTest(set='v2' if v2set else 'v1', get='v2' if v2get else 'v1'):
                self._test_bad_guesses_clears_pin_impl(v2set, v2get)

    def _test_bad_server_key_breaks_impl(self, use_v2_protocol):
        # Reinitialise keys and secret
        privkey, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()
        pin_aes_key = bytes(os.urandom(32))

        # Set and verify the the pin - check this creates the file
        v2_replay_counter = b'\x00\x00\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Check we can get the key
        v2_replay_counter = b'\x01\x00\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Bad server key
        for attempt in range(6):
            # Attempt to get with bad server key (using same entropy)
            bad_key = os.urandom(32)
            v2_replay_counter = (10 + attempt).to_bytes(4, 'little') if use_v2_protocol else None
            payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
            guesskey = PINDb.get_aes_key(cke, payload, bad_key, v2_replay_counter)

            # Wrong key should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after many failed attempts server keeps the file
        # as it doesn't know what file to check even
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Now the correct pin will should still work if correct server key used
        v2_replay_counter = b'\x00\xff\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertTrue(compare_digest(aeskey, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_bad_server_key_pub_key_breaks(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_bad_server_key_breaks_impl(use_v2_protocol)

    def _test_bad_user_pubkey_breaks_impl(self, use_v2_protocol):
        # Reinitialise keys and secret
        privkey, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()
        pin_aes_key = bytes(os.urandom(32))

        # Set and verify the the pin - check this creates the file
        v2_replay_counter = b'\x00\x00\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Check we can get the key
        v2_replay_counter = b'\x03\x00\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Bad replay counter passed from client
        for attempt in range(6):
            # Attempt to get with bad pub_key (using same entropy)
            bad_key = os.urandom(32)
            v2_replay_counter = (10 + attempt).to_bytes(4, 'little') if use_v2_protocol else None
            bad_payload = self.make_payload(bad_key, cke, pin_secret, entropy, v2_replay_counter)
            guesskey = PINDb.get_aes_key(cke, bad_payload, pin_aes_key, v2_replay_counter)

            # Wrong pubkey should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after many failed attempts server keeps the file
        # as it doesn't know what file to check even
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Now the correct pin will should still be correct if correct pubkey used
        v2_replay_counter = b'\x00\xff\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertTrue(compare_digest(aeskey, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_bad_user_pub_key_breaks(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_bad_user_pubkey_breaks_impl(use_v2_protocol)

    def test_bad_v2_counter_breaks_get_pin(self):
        # Reinitialise keys and secret
        privkey, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()
        pin_aes_key = bytes(os.urandom(32))

        # Set and verify the the pin - check this creates the file
        v2_replay_counter = b'\x00\x00\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Check we can get the key with increasing counters, and same or
        # decreasing counters give a 'bad pin' result
        max_counter = 0
        for counter in [0, 3, 3, 6, 123, 45, 332, 155, 332, 330, 500, 200, 300, 400, 501, 500]:
            v2_replay_counter = counter.to_bytes(4, 'little', signed=False)
            payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
            aeskey = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)

            if counter > max_counter:
                # Should get correct key
                self.assertTrue(compare_digest(aeskey, aeskey_s))
                max_counter = counter
            else:
                # Should get incorrect key
                self.assertFalse(compare_digest(aeskey, aeskey_s))

        # Now the correct pin will should still be correct
        assert max_counter == 501

        v2_replay_counter = b'\x00\xff\xff\xff'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertTrue(compare_digest(aeskey, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_bad_v2_counter_breaks_set_pin(self):
        # Reinitialise keys and secret
        privkey, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()
        pin_aes_key = bytes(os.urandom(32))

        # Set and verify the the pin - check this creates the file
        v2_replay_counter = b'\x00\x00\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        self.assertFalse(PINDb.storage.exists(pinfile))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        self.assertTrue(PINDb.storage.exists(pinfile))

        v2_replay_counter = b'\x05\x00\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Set-pin fails if use a non-zero counter
        v2_replay_counter = b'\x0f\x0f\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        with self.assertRaises(AssertionError) as cm:
            aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)

        # Key still present and readable with lower counter as set failed
        v2_replay_counter = b'\x06\x00\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

        # Set-pin must use a counter of 0
        v2_replay_counter = b'\x00\x00\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)

        # Key readable with new counter
        v2_replay_counter = b'\x01\x00\x00\x00'
        payload = self.make_payload(privkey, cke, pin_secret, entropy, v2_replay_counter)
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))

    def _test_two_users_with_same_pin_impl(self, v2X, v2Y):
        # Get two sets of keys and a new secret
        privX, pubX, ckeX, _ = self.new_keys()
        privY, pubY, ckeY, _ = self.new_keys()
        secret_in, entropy_in = self.new_pin_secret(), self.new_entropy()

        # Build the expected payloads
        # X and Y use the same values... bizarre but should be fine
        v2_replay_counterX = b'\x00\x00\x00\x00' if v2X else None
        v2_replay_counterY = b'\x00\x00\x00\x00' if v2Y else None
        payloadX = self.make_payload(privX, ckeX, secret_in, entropy_in, v2_replay_counterX)
        payloadY = self.make_payload(privY, ckeY, secret_in, entropy_in, v2_replay_counterY)
        pin_aes_key = bytes(os.urandom(32))
        aeskeyX_s = PINDb.set_pin(ckeX, payloadX, pin_aes_key, v2_replay_counterX)
        aeskeyY_s = PINDb.set_pin(ckeY, payloadY, pin_aes_key, v2_replay_counterY)

        # Keys should be different
        self.assertEqual(len(aeskeyX_s), len(aeskeyY_s))
        self.assertFalse(compare_digest(aeskeyX_s, aeskeyY_s))

        # Each can get their own key
        v2_replay_counterX = os.urandom(4) if v2X else None
        v2_replay_counterY = os.urandom(4) if v2Y else None
        payloadX = self.make_payload(privX, ckeX, secret_in, entropy_in, v2_replay_counterX)
        payloadY = self.make_payload(privY, ckeY, secret_in, entropy_in, v2_replay_counterY)
        aeskeyX_g = PINDb.get_aes_key(ckeX, payloadX, pin_aes_key, v2_replay_counterX)
        aeskeyY_g = PINDb.get_aes_key(ckeY, payloadY, pin_aes_key, v2_replay_counterY)
        self.assertFalse(compare_digest(aeskeyX_g, aeskeyY_g))
        self.assertTrue(compare_digest(aeskeyX_g, aeskeyX_s))
        self.assertTrue(compare_digest(aeskeyY_g, aeskeyY_s))

    def test_two_users_with_same_pin(self):
        for v2X, v2Y in [(False, False), (False, True), (True, True)]:
            with self.subTest(X='v2' if v2X else 'v1', Y='v2' if v2Y else 'v1'):
                self._test_two_users_with_same_pin_impl(v2X, v2Y)

    def _test_rejects_without_client_entropy_impl(self, use_v2_protocol):
        # Reinitialise keys and secret and entropy
        sig_priv, _, cke, pinfile = self.new_keys()
        secret, entropy = self.new_pin_secret(), bytearray()

        # Build the expected payload
        v2_replay_counter = b'\x00\x00\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(sig_priv, cke, secret, entropy, v2_replay_counter)

        pin_aes_key = bytes(os.urandom(32))
        with self.assertRaises(AssertionError) as cm:
            PINDb.set_pin(cke, payload, pin_aes_key, v2_replay_counter)

        v2_replay_counter = b'\x01\x00\x00\x00' if use_v2_protocol else None
        payload = self.make_payload(sig_priv, cke, secret, entropy, v2_replay_counter)
        with self.assertRaises(AssertionError) as cm:
            PINDb.get_aes_key(cke, payload, pin_aes_key, v2_replay_counter)

    def test_rejects_without_client_entropy(self):
        for use_v2_protocol in [False, True]:
            with self.subTest(protocol='v2' if use_v2_protocol else 'v1'):
                self._test_rejects_without_client_entropy_impl(use_v2_protocol)


if __name__ == '__main__':
    unittest.main()
