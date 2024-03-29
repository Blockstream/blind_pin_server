import unittest

import os

from ..client import PINClientECDHv2
from ..server import PINServerECDHv2


# Tests ECDHv2 wrapper without any reference to the pin/aes-key paylod stuff.
# Just testing the ECDH envelope/encryption in isolation, with misc bytearray()
# payloads (ie. any old str.encode()).  Tests client/server handshake/pairing.
# NOTE: protocol v2:
# 'hmac' fields and derived keys implicit, and no key-exchange handshake required
class ECDHv2Test(unittest.TestCase):
    REPLAY_COUNTER = bytes([0x00, 0x00, 0x00, 0x2a])  # arbitrary

    @classmethod
    def setUpClass(cls):
        # The server public key the client would know
        with open(PINServerECDHv2.STATIC_SERVER_PUBLIC_KEY_FILE, 'rb') as f:
            cls.static_server_public_key = f.read()

    # Make a new client and initialise with server tweaked key and initial counter
    def new_client_handshake(self):
        client = PINClientECDHv2(self.static_server_public_key, self.REPLAY_COUNTER)
        ske, cke = client.get_key_exchange()
        return cke, client

    def _test_client_server_impl(self, client_request, server_response):

        # A new client is created, which computes the ske from a tweak on the
        # server static key.
        cke, client = self.new_client_handshake()

        # The client can then encrypt a payload (with implicit hmac) for the server
        encrypted = client.encrypt_request_payload(client_request)
        self.assertNotEqual(client_request, encrypted)

        # A new server is created when passed the client replay-counter.
        # The server uses the cke and counter to create the tweaked *private* key
        # NOTE: the server deduced private key should be the counterpart to the
        # client-deduced public key - if so the payload decryption should yield
        # the original cleartext request message.
        server = PINServerECDHv2(client.replay_counter, cke)
        received = server.decrypt_request_payload(cke, encrypted)
        self.assertEqual(received, client_request)

        # The server can then send an encrypted response to the client
        encrypted = server.encrypt_response_payload(cke, server_response)

        # The client can decrypt the response.
        # Note: this validates the implicit hmac before it decrypts/returns
        received = client.decrypt_response_payload(encrypted)
        self.assertEqual(received, server_response)

    def test_client_server_happypath(self):
        for (request, response) in [
                ('REQUEST'.encode(), 'RESPONSE'.encode()),
                ('12345 request string'.encode(), '67890 reply'.encode()),
                (os.urandom(32), os.urandom(64))
        ]:
            with self.subTest(request=request, response=response):
                self._test_client_server_impl(request, response)

    def test_call_with_payload(self):
        # Client sends message to server
        cke, client = self.new_client_handshake()
        client_request = "Hello - test 123".encode()
        encrypted = client.encrypt_request_payload(client_request)
        self.assertNotEqual(client_request, encrypted)

        # Test server un-/re-wrapping function - this handles all the ecdh
        # decrypting, hmac checking and encrypting/hmac-ing of the response.
        # Handler need know nothing about the wrapping encryption.
        server = PINServerECDHv2(client.replay_counter, cke)
        server_response = "Reply to 'test 123' message".encode()

        def _func(client_key, payload, aes_pin_data_key, replay_counter):
            self.assertEqual(client_key, cke)
            self.assertEqual(payload, client_request)
            self.assertEqual(replay_counter, client.replay_counter)
            return server_response

        encrypted = server.call_with_payload(cke, encrypted, _func)

        # Assert that is what the client expects
        received = client.decrypt_response_payload(encrypted)
        self.assertEqual(received, server_response)

    def test_multiple_calls(self):
        # A new server and client
        cke, client = self.new_client_handshake()
        server = PINServerECDHv2(client.replay_counter, cke)

        # Server can handle multiple calls from the client with same secrets
        # (But that would use same cke and counter which is ofc not ideal/recommended.)
        for i in range(5):
            client_request = 'request-{}'.format(i).encode()
            encrypted = client.encrypt_request_payload(client_request)

            received = server.decrypt_request_payload(cke, encrypted)
            self.assertEqual(received, client_request)

            server_response = 'response-{}'.format(i).encode()
            encrypted = server.encrypt_response_payload(cke, server_response)

            received = client.decrypt_response_payload(encrypted)
            self.assertEqual(received, server_response)

    def test_bad_request_cke_throws(self):
        # A new server and client
        cke, client = self.new_client_handshake()
        server = PINServerECDHv2(client.replay_counter, cke)

        # Encrypt message
        client_request = 'bad-cke-request'.encode()
        encrypted = client.encrypt_request_payload(client_request)

        # Break cke
        bad_cke, _ = self.new_client_handshake()
        self.assertEqual(len(cke), len(bad_cke))
        self.assertNotEqual(cke, bad_cke)

        # Ensure decrypt_request() throws
        server.generate_shared_secrets(cke)
        server.decrypt_request_payload(cke, encrypted)  # no error

        # New server with bad_cke from the get go
        server = PINServerECDHv2(client.replay_counter, bad_cke)
        with self.assertRaises(ValueError) as cm:
            server.decrypt_request_payload(bad_cke, encrypted)  # error

        # Ensure call_with_payload() throws before it calls the handler fn
        def _func(client_key, payload, aes_pin_data_key):
            self.fail('should-never-get-here')

        with self.assertRaises(ValueError) as cm:
            server.call_with_payload(bad_cke, encrypted, _func)

    def test_bad_request_counter_throws(self):
        # A new server and client
        cke, client = self.new_client_handshake()
        server = PINServerECDHv2(client.replay_counter, cke)

        # Encrypt message
        client_request = 'bad-counter-request'.encode()
        encrypted = client.encrypt_request_payload(client_request)

        # Ensure decrypt_request() throws
        server.generate_shared_secrets(cke)
        server.decrypt_request_payload(cke, encrypted)  # no error

        # New server with bad counter passed
        server = PINServerECDHv2(os.urandom(4), cke)
        with self.assertRaises(ValueError) as cm:
            server.decrypt_request_payload(cke, encrypted)  # error

        # Ensure call_with_payload() throws before it calls the handler fn
        def _func(client_key, payload, aes_pin_data_key):
            self.fail('should-never-get-here')

        with self.assertRaises(ValueError) as cm:
            server.call_with_payload(cke, encrypted, _func)

    def test_bad_request_hmac_throws(self):
        # A new server and client
        cke, client = self.new_client_handshake()
        server = PINServerECDHv2(client.replay_counter, cke)

        # Encrypt message
        client_request = 'bad-hmac-request'.encode()
        encrypted = client.encrypt_request_payload(client_request)

        # Break hmac at tail of encrypted bytes
        bad_hmac = bytearray(b+1 if b < 255 else b-1 for b in encrypted[-32:])
        bad_encrypted = encrypted[:-32] + bad_hmac
        self.assertEqual(encrypted[:-32], bad_encrypted[:-32])
        self.assertNotEqual(encrypted[-32:], bad_encrypted[-32:])

        # Ensure decrypt_request() throws
        server.decrypt_request_payload(cke, encrypted)  # no error
        with self.assertRaises(ValueError) as cm:
            server.decrypt_request_payload(cke, bad_encrypted)  # error

        # Ensure call_with_payload() throws before it calls the handler fn
        def _func(client_key, payload, aes_pin_data_key, replay_counter):
            self.fail('should-never-get-here')

        with self.assertRaises(ValueError) as cm:
            server.call_with_payload(cke, bad_encrypted, _func)

    def test_bad_response_hmac_throws(self):
        # A new server and client
        cke, client = self.new_client_handshake()
        server = PINServerECDHv2(client.replay_counter, cke)

        # Encrypt message
        client_request = 'bad-hmac-response-request'.encode()
        encrypted = client.encrypt_request_payload(client_request)

        def _func(client_key, payload, pin_data_aes_key, replay_counter):
            self.assertEqual(client_key, cke)
            self.assertEqual(payload, client_request)
            self.assertEqual(replay_counter, client.replay_counter)
            return 'bad-hmac-response'.encode()

        encrypted = server.call_with_payload(cke, encrypted, _func)

        # Break hmac
        bad_hmac = bytearray(b+1 if b < 255 else b-1 for b in encrypted[-32:])
        bad_encrypted = encrypted[:-32] + bad_hmac
        self.assertEqual(encrypted[:-32], bad_encrypted[:-32])
        self.assertNotEqual(encrypted[-32:], bad_encrypted[-32:])

        client.decrypt_response_payload(encrypted)  # No error
        with self.assertRaises(ValueError) as cm:
            client.decrypt_response_payload(bad_encrypted)  # error


if __name__ == '__main__':
    unittest.main()
