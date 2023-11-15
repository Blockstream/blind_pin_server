import time
import json
import os
from flask import Flask, request, jsonify
from .server import PINServerECDH, PINServerECDHv1, PINServerECDHv2
from .pindb import PINDb
from wallycore import AES_KEY_LEN_256, AES_BLOCK_LEN, HMAC_SHA256_LEN
from dotenv import load_dotenv

# Time we will retain active sessions, in seconds.
# ie. maximum time allowed 'start_handshake' (which creates the session)
# and the get-/set-pin call, which utilises it.
# Can be set in environment, defaults to 5mins
load_dotenv()
SESSION_LIFETIME = int(os.environ.get('SESSION_LIFETIME', 300))


def flask_server():
    # Load, verify, and cache server static key at startup
    # (Refuse to start if key non-existing or invalid)
    PINServerECDH.load_private_key()

    sessions = {}
    app = Flask(__name__)

    def _cleanup_expired_sessions():
        nonlocal sessions
        time_now = int(time.time())
        sessions = dict(filter(
            lambda s: time_now - s[1].time_started < SESSION_LIFETIME,
            sessions.items()))

    @app.route('/', methods=['GET'])
    def alive():
        return ""

    @app.route('/start_handshake', methods=['POST'])
    def start_handshake_route():
        app.logger.debug('Number of sessions {}'.format(len(sessions)))

        # Create a new ephemeral server/session and get its signed pubkey
        e_ecdh_server = PINServerECDHv1()
        pubkey, sig = e_ecdh_server.get_signed_public_key()
        ske = pubkey.hex()

        # Cache new session
        _cleanup_expired_sessions()
        sessions[ske] = e_ecdh_server

        # Return response
        return jsonify({'ske': ske,
                        'sig': sig.hex()})

    # NOTE: explicit 'hmac' fields in protocol v1
    def _complete_server_call_v1(pin_func, udata):
        ske = udata['ske']
        assert 'replay_counter' not in udata

        # Get associated session (ensuring not stale)
        _cleanup_expired_sessions()
        e_ecdh_server = sessions[ske]

        # get/set pin and get response data
        encrypted_key, hmac = e_ecdh_server.call_with_payload(
                bytes.fromhex(udata['cke']),
                bytes.fromhex(udata['encrypted_data']),
                bytes.fromhex(udata['hmac_encrypted_data']),
                pin_func)

        # Expecting to return an encrypted aes-key with separate hmac
        assert len(encrypted_key) == AES_KEY_LEN_256 + (2*AES_BLOCK_LEN)
        assert len(hmac) == HMAC_SHA256_LEN

        # Cleanup session
        del sessions[ske]
        _cleanup_expired_sessions()

        # Return response
        return jsonify({'encrypted_key': encrypted_key.hex(),
                        'hmac': hmac.hex()})

    # NOTE: 'hmac' data is appened to encrypted_data in protocol v2
    def _complete_server_call_v2(pin_func, udata):
        assert 'ske' not in udata
        assert len(udata['replay_counter']) == 8
        cke = bytes.fromhex(udata['cke'])
        replay_counter = bytes.fromhex(udata['replay_counter'])
        e_ecdh_server = PINServerECDHv2(replay_counter, cke)
        encrypted_key = e_ecdh_server.call_with_payload(
                cke,
                bytes.fromhex(udata['encrypted_data']),
                pin_func)

        # Expecting to return an encrypted aes-key with hmac appended
        assert len(encrypted_key) == AES_KEY_LEN_256 + (2*AES_BLOCK_LEN) + HMAC_SHA256_LEN

        # Return response
        return jsonify({'encrypted_key': encrypted_key.hex()})

    def _complete_server_call(pin_func):
        try:
            # Get request data
            udata = json.loads(request.data)
            if 'replay_counter' in udata:
                return _complete_server_call_v2(pin_func, udata)
            return _complete_server_call_v1(pin_func, udata)

        except Exception as e:
            app.logger.error("Error: {} {}".format(type(e), e))
            app.logger.error("Request body: {}".format(request.data))
            raise e

    @app.route('/get_pin', methods=['POST'])
    def get_pin_route():
        return _complete_server_call(PINDb.get_aes_key)

    @app.route('/set_pin', methods=['POST'])
    def set_pin_route():
        return _complete_server_call(PINDb.set_pin)

    return app


app = flask_server()
