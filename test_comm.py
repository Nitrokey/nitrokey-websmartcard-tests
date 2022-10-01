#
# Copyright (c) 2022 Nitrokey GmbH.
#
# This file is part of Nitrokey Webcrypt
# (see https://github.com/Nitrokey/nitrokey-webcrypt).
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
#
import functools
import hmac
import struct
from hashlib import sha256

import ecdsa
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from ecdsa import NIST256p
from ecdsa.ecdh import ECDH
from pynitrokey.fido2.client import NKFido2Client as NKFido2Client
from tinyec import registry

from conftest import TEST_DATA, fixture_data_big, fixture_data_random, TEST_DATA_SMALL, fixture_data_medium, Constants
from webcrypt.communication import device_receive, device_send, send_and_receive, set_temporary_password
from webcrypt.helpers import compare_cbor_dict, log_data, cbor_loads
from webcrypt.llog import get_logger
from webcrypt.types import Command, ExecError

SALT = b'salt' * 4
curve = registry.get_curve('secp256r1')

log = get_logger()


def test_setup(run_on_hardware):
    pass


@pytest.mark.parametrize("test_data", [
    bytes(range(64)),  # 54 is max what is working
    bytes(range(64 * 2)),  # 54 is max what is working
    dict(B=bytes(range(64))),  # 54 is max what is working
    dict(ABCD='BB' * 5),
    TEST_DATA,
    TEST_DATA_SMALL,
    dict(key=b'Z' * 255),  # 54 is max what is working
    dict(key=bytes(range(255))),  # 54 is max what is working
    fixture_data_medium(),
    fixture_data_big(),
    fixture_data_random(),
    dict(key=b'Z' * 400),  # ping data should be structure independent
    dict(key=b'Z' * 900),  # ping data should be structure independent
    dict(key=b'Z' * (1024 - 71 - 1 - 8)),  # ping data should be structure independent FIXME handle edge case
])
def test_ping(nkfido2_client: NKFido2Client, test_data: dict):
    """Sends arbitrary dict structure over the wire, and receives the same data"""
    assert device_send(nkfido2_client, test_data, Command.TEST_PING)
    commandID, read_data_bytes = device_receive(nkfido2_client)
    assert commandID == Command.TEST_PING.value[0]
    compare_cbor_dict(read_data_bytes, test_data)


# @pytest.mark.skip


@pytest.mark.parametrize("ping_len", [
    # 56,
    # 57,
    100,
    # 512,
    980,
    # 990,
    # *list(range(981, 991, 1)),
])
def test_ping_2(nkfido2_client: NKFido2Client, ping_len: int):
    assert ping_len < 2000
    """Sends arbitrary dict structure over the wire, and receives the same data"""
    d = dict(k=b'A' * ping_len)
    success, read_data_bytes = send_and_receive(nkfido2_client, Command.TEST_PING, d)
    compare_cbor_dict(read_data_bytes, d)


def helper_login(nkfido2_client: NKFido2Client, PIN: bytes, expected_error=None):
    s, data = send_and_receive(nkfido2_client, Command.SET_PIN, dict(PIN=PIN), check=False)

    s, data = send_and_receive(nkfido2_client, Command.LOGIN, dict(PIN=PIN), expected_error=expected_error)
    if not expected_error:
        d = cbor_loads(data)
        set_temporary_password(d['TP'])
        # todo check if that is needed
        STATE["TP"] = d["TP"]


@functools.lru_cache(maxsize=None)
def test_setup_session(nkfido2_client):
    log.debug('Setting session')
    send_and_receive(nkfido2_client, Command.FACTORY_RESET)
    helper_login(nkfido2_client, Constants.PIN)


STATE = {
    "PUBKEY": b"",
    "KEYHANDLE": b"",
}


def helper_view_dict(d: dict):
    for k, v in d.items():
        vv = v
        if isinstance(v, bytes):
            vv = v.hex()
        log.debug(f'{k}: {len(v)} {vv}')


def helper_view_list(l: list):
    for k, v in enumerate(l):
        vv = v
        if isinstance(v, bytes):
            vv = v.hex()
        log.debug(f'{k}: {len(v)} {vv}')


def helper_view_data(d, msg: str = ''):
    if msg:
        log.debug(msg.center(60, '='))
    if isinstance(d, dict):
        return helper_view_dict(d)
    elif isinstance(d, list):
        return helper_view_list(d)
    else:
        log.debug(d)
    if msg:
        log.debug('+'.center(60, '='))


def helper_update_state(new_state: dict):
    global STATE
    STATE = new_state
    helper_view_dict(STATE)


@pytest.mark.repeat(10)
def test_generate(nkfido2_client):
    read_data = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY)
    helper_view_data(read_data)
    assert isinstance(read_data, dict)
    assert check_keys_in_received_dictionary(read_data, ["PUBKEY", "KEYHANDLE"])
    helper_update_state(read_data)
    read_data2 = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY)
    for k in read_data.keys():
        assert read_data2[k] != read_data[k]

    log.debug(f'pubkey: {len(read_data["PUBKEY"])} {read_data["PUBKEY"].hex()}')

    vk = ecdsa.VerifyingKey.from_string(read_data["PUBKEY"],
                                        curve=ecdsa.NIST256p,
                                        hashfunc=sha256)
    log.debug(f'imported key: {vk=}')


def test_generate_from_data(nkfido2_client):
    data = {"HASH": sha256(b"test").digest()}
    read_data = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    helper_view_data(read_data)
    assert isinstance(read_data, dict)
    assert check_keys_in_received_dictionary(read_data, ["PUBKEY", "KEYHANDLE"])
    helper_update_state(read_data)

    # try again with the same data - the public key should remain the same
    read_data = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    assert read_data["PUBKEY"] == STATE["PUBKEY"]

    # try again with the different data - the public key should change
    data = {"HASH": sha256(b"test2").digest()}
    read_data = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    assert read_data["PUBKEY"] != STATE["PUBKEY"]

    # try again with the same data as initially sent - the public key should remain the same
    data = {"HASH": sha256(b"test").digest()}
    read_data = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    assert read_data["PUBKEY"] == STATE["PUBKEY"]


def test_sign_bad_keyhandle(nkfido2_client):
    # TODO add test like this to every command accepting it
    message = b"test_message"
    hash_data = sha256(message).digest()
    kh = STATE["KEYHANDLE"]
    kh = b'x' + kh[1:]
    data = {'HASH': hash_data, "KEYHANDLE": kh}
    helper_view_data(data)
    send_and_receive(nkfido2_client, Command.SIGN, data, expected_error=ExecError.ERR_BAD_FORMAT)


@pytest.mark.parametrize("curve", [
    # pytest.param('secp256k1',
    #              marks=pytest.mark.xfail(reason='curve must be enabled in the firmware to work')),
    pytest.param('secp256r1')
    # marks=pytest.mark.xfail(reason='not implemented')),
])
@pytest.mark.repeat(10)
def test_sign(nkfido2_client, curve):
    global STATE
    assert STATE
    assert "KEYHANDLE" in STATE and STATE["KEYHANDLE"], "test_generate needs to be run first"

    message = b"test_message"
    hash_data = sha256(message).digest()
    data = {'HASH': hash_data, "KEYHANDLE": STATE["KEYHANDLE"]}
    log.debug(
        f'Used data for SIGN: {data["HASH"].hex()} {len(data["HASH"])} {data["KEYHANDLE"].hex()} {len(data["KEYHANDLE"])}')
    read_data = send_and_receive_cbor(nkfido2_client, Command.SIGN, data)
    helper_view_data(read_data)
    assert isinstance(read_data, dict)
    assert check_keys_in_received_dictionary(read_data, ["INHASH", "SIGNATURE"])
    assert hash_data == read_data["INHASH"]

    signature = read_data["SIGNATURE"]
    pubkey = STATE["PUBKEY"]
    helper_view_data(STATE)
    if curve == 'secp256k1':
        signature__hex = signature.hex()
        pubkey__hex = pubkey.hex()
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey__hex), curve=ecdsa.SECP256k1,
                                            hashfunc=sha256)
        assert vk.verify(bytes.fromhex(signature__hex), message)
    elif curve == 'secp256r1':
        vk = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.NIST256p, hashfunc=sha256)
        assert vk.verify(signature, hash_data, hashfunc=sha256)
    else:
        assert False, 'Unsupported curve option'


def round_to_next(x, n):
    return x + n - x % n


@pytest.mark.parametrize("param", [
    (16, 16, 32),
    (15, 16, 16),
    (1, 16, 16),
    (0, 16, 16),
])
def test_helper_round(param):
    (x, n, result) = param
    assert result == round_to_next(x, n)


def encrypt_AES(msg, secretKey):
    # PKCS#7 padding
    len_rounded = round_to_next(len(msg), 16)
    msg = msg.ljust(len_rounded, int.to_bytes(len_rounded - len(msg), 1, 'little'))
    log.debug(f'msg={msg}')
    aesCipher = AES.new(secretKey, AES.MODE_CBC, IV=b'\0' * 16)
    ciphertext = aesCipher.encrypt(msg)
    return ciphertext


@pytest.mark.parametrize("send_correct_hmac", [
    True,
    False,
])
def test_decrypt(nkfido2_client, send_correct_hmac):
    assert "KEYHANDLE" in STATE, "test_generate needs to be run first"

    msg = b'Text to be encrypted by ECC public key and ' \
          b'decrypted by its corresponding ECC private key'
    log.debug(f"original msg: {msg}")

    ecdh = ECDH(curve=NIST256p)
    ecdh.generate_private_key()
    local_public_key = ecdh.get_public_key()
    ecdh.load_received_public_key_bytes(STATE["PUBKEY"])
    secretKey = ecdh.generate_sharedsecret_bytes()
    ephem_pub_bin = local_public_key.to_string()
    ciphertext = encrypt_AES(msg, secretKey)

    data_len = struct.pack("<H", len(ciphertext))

    log.debug(secretKey.hex())
    h = hmac.new(secretKey, digestmod='sha256')
    h.update(ciphertext)
    h.update(ephem_pub_bin)
    if send_correct_hmac:
        # skip one of the parameters while calculating digest to get invalid HMAC (test purposes only)
        h.update(data_len)
    h.update(STATE["KEYHANDLE"])
    hmac_res = h.digest()

    data = {
        'DATA': ciphertext,
        "KEYHANDLE": STATE["KEYHANDLE"],
        "HMAC": hmac_res,
        "ECCEKEY": ephem_pub_bin,
    }

    helper_view_data(data)

    success, read_data_bytes = send_and_receive(nkfido2_client, Command.DECRYPT, data,
                                                expected_error=None if send_correct_hmac else ExecError.ERR_INVALID_CHECKSUM)

    if send_correct_hmac:
        assert success
        read_data = cbor_loads(read_data_bytes)
        helper_view_data(read_data)
        assert isinstance(read_data, dict)
        assert check_keys_in_received_dictionary(read_data, ["DATA"])

        log.debug(f"decrypted msg device: {read_data['DATA']}")
        assert msg.hex() in read_data["DATA"].hex()
        pkcs1_fill = -read_data["DATA"][-1]
        assert msg == read_data["DATA"][:pkcs1_fill]
    else:
        assert len(read_data_bytes) == 0


def test_decrypt_rsa_rk(nkfido2_client):
    helper_login(nkfido2_client, Constants.PIN)
    RSA_KEY_PATH = 'k1.rsa.ser'
    with open(RSA_KEY_PATH, 'rb') as f:
        rsa_data = f.read()
    data = {"RAW_KEY_DATA": rsa_data, "KEY_TYPE": 1}
    read_data = send_and_receive_cbor(nkfido2_client, Command.WRITE_RESIDENT_KEY, data)
    helper_view_dict(read_data)
    assert check_keys_in_received_dictionary(read_data, ["PUBKEY", "KEYHANDLE"])
    keyhandle = read_data["KEYHANDLE"]

    # encrypt
    plaintext = b"test_message"
    with open(RSA_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_der_private_key(
            key_file.read(), None)
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(plaintext=plaintext, padding=padding.PKCS1v15())

    # decrypt
    data = {
        'DATA': ciphertext,
        "KEYHANDLE": keyhandle,
        "HMAC": b"",
        "ECCEKEY": b"",
    }

    read_data = send_and_receive_cbor(nkfido2_client, Command.DECRYPT, data)
    assert check_keys_in_received_dictionary(read_data, ["DATA"])
    assert read_data["DATA"] == plaintext


def test_status(nkfido2_client: NKFido2Client):
    read_data = send_and_receive_cbor(nkfido2_client, Command.STATUS)
    log.debug(read_data)
    assert check_keys_in_received_dictionary(read_data, ["UNLOCKED", "VERSION", "SLOTS", "PIN_ATTEMPTS"])

    send_and_receive(nkfido2_client, Command.LOGOUT)
    read_data = send_and_receive_cbor(nkfido2_client, Command.STATUS)
    assert not read_data["UNLOCKED"]

    helper_login(nkfido2_client, Constants.PIN)
    read_data = send_and_receive_cbor(nkfido2_client, Command.STATUS)
    assert read_data["UNLOCKED"]


def send_and_receive_cbor(*args, **kwargs):
    success, read_data_bytes = send_and_receive(*args, **kwargs)
    read_data = cbor_loads(read_data_bytes)
    return read_data


def check_keys_in_received_dictionary(data: dict, keys: list):
    return all(x in data for x in keys)


def test_initialize_simple(nkfido2_client: NKFido2Client):
    read_data = send_and_receive_cbor(nkfido2_client, Command.INITIALIZE_SEED)
    # TODO do not check for the master and salt while using trussed as a platform
    assert check_keys_in_received_dictionary(read_data, ["MASTER", "SALT"])


def test_initialize_simple2(nkfido2_client: NKFido2Client):
    read_data = send_and_receive_cbor(nkfido2_client, Command.INITIALIZE_SEED)
    read_data2 = send_and_receive_cbor(nkfido2_client, Command.INITIALIZE_SEED)
    assert check_keys_in_received_dictionary(read_data, ["MASTER", "SALT"])
    assert check_keys_in_received_dictionary(read_data2, ["MASTER", "SALT"])
    assert read_data["MASTER"]
    assert read_data["MASTER"] != read_data2["MASTER"]
    helper_view_data(read_data, "initialization - read data")
    helper_view_data(read_data2)


def test_initialize(nkfido2_client: NKFido2Client):
    data = {"HASH": sha256(b"test").digest()}
    key1 = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    key1b = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    assert key1["PUBKEY"].hex() == key1b["PUBKEY"].hex()
    send_and_receive_cbor(nkfido2_client, Command.INITIALIZE_SEED)
    key2 = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    key2b = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data)
    assert key1["PUBKEY"].hex() != key2["PUBKEY"].hex()
    assert key2b["PUBKEY"].hex() == key2["PUBKEY"].hex()


def test_restore_simple(nkfido2_client: NKFido2Client):
    data = {"MASTER": b'1' * 32, "SALT": b'2' * 8}
    read_data = send_and_receive_cbor(nkfido2_client, Command.RESTORE_FROM_SEED, data)
    log.debug(read_data)
    assert check_keys_in_received_dictionary(read_data, ["HASH"])


@pytest.mark.parametrize("test_input", [
    # (b'0' * 32, b'0' * 8),  # firstly set all to zero
    # (b'0' * 32, b'1' * 8),  # check if changing only salts changes the generated keys

    # do not check SALT changes for now
    (b'0' * 32, b'0' * 8),  # reset all to zero again
    (b'1' * 32, b'0' * 8),  # check if changing only master changes the generated keys
    (b'0' * 32, b'0' * 8),  # reset all to zero again
])
def test_restore(nkfido2_client: NKFido2Client, test_input):
    master, salt = test_input
    data_key = {"HASH": sha256(b"test").digest()}
    data = {"MASTER": master, "SALT": salt}
    key1 = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data_key)
    key1b = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data_key)
    assert key1["PUBKEY"].hex() == key1b["PUBKEY"].hex()
    send_and_receive_cbor(nkfido2_client, Command.RESTORE_FROM_SEED, data)
    key2 = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data_key)
    assert key1["PUBKEY"].hex() != key2["PUBKEY"].hex()



def test_PIN_attempts_deprecated(nkfido2_client: NKFido2Client):
    send_and_receive(nkfido2_client, Command.PIN_ATTEMPTS, expected_error=ExecError.ERR_INVALID_COMMAND)


def test_resident_keys_generate(nkfido2_client: NKFido2Client):
    read_data = send_and_receive_cbor(nkfido2_client, Command.GENERATE_RESIDENT_KEY)
    helper_view_dict(read_data)
    assert check_keys_in_received_dictionary(read_data, ["PUBKEY", "KEYHANDLE"])


def test_resident_keys_write(nkfido2_client: NKFido2Client):
    helper_login(nkfido2_client, Constants.PIN)
    data = {"RAW_KEY_DATA": b'a'*32}
    read_data = send_and_receive_cbor(nkfido2_client, Command.WRITE_RESIDENT_KEY, data)
    helper_view_dict(read_data)
    assert check_keys_in_received_dictionary(read_data, ["PUBKEY", "KEYHANDLE"])

    message = b"test_message"
    hash_data = sha256(message).digest()
    data = {'HASH': hash_data, "KEYHANDLE": read_data["KEYHANDLE"]}
    read_data = send_and_receive_cbor(nkfido2_client, Command.SIGN, data)

    helper_view_data(read_data)
    assert isinstance(read_data, dict)
    assert check_keys_in_received_dictionary(read_data, ["INHASH", "SIGNATURE"])
    assert hash_data == read_data["INHASH"]


def test_resident_keys_write_rsa(nkfido2_client: NKFido2Client):
    helper_login(nkfido2_client, Constants.PIN)
    RSA_KEY_PATH = 'k1.rsa.ser'
    with open(RSA_KEY_PATH, 'rb') as f:
        rsa_data = f.read()
    data = {"RAW_KEY_DATA": rsa_data, "KEY_TYPE": 1}
    read_data = send_and_receive_cbor(nkfido2_client, Command.WRITE_RESIDENT_KEY, data)
    helper_view_dict(read_data)
    assert check_keys_in_received_dictionary(read_data, ["PUBKEY", "KEYHANDLE"])
    public_key_webcrypt = read_data["PUBKEY"]

    message = b"test_message"
    hash_data = sha256(message).digest()
    keyhandle_written_resident_key = read_data["KEYHANDLE"]
    data = {'HASH': hash_data, "KEYHANDLE": keyhandle_written_resident_key}
    read_data = send_and_receive_cbor(nkfido2_client, Command.SIGN, data)

    helper_view_data(read_data)
    assert isinstance(read_data, dict)
    assert check_keys_in_received_dictionary(read_data, ["INHASH", "SIGNATURE"])
    assert hash_data == read_data["INHASH"]
    rsa_signature = read_data["SIGNATURE"]

    # validate signature
    with open(RSA_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_der_private_key(
            key_file.read(), None)
    public_key = private_key.public_key()
    public_key.verify(
        rsa_signature,
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # public key generation check
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )
    assert public_key_der.hex() == public_key_webcrypt.hex()

    # read public key
    data = {"KEYHANDLE": keyhandle_written_resident_key}
    read_public_key = send_and_receive_cbor(nkfido2_client, Command.READ_RESIDENT_KEY_PUBLIC, data)["PUBKEY"]
    assert read_public_key.hex() == public_key_der.hex()


@pytest.mark.parametrize("iter", [1, 10])
def test_resident_keys_read_public_key(nkfido2_client: NKFido2Client, iter):
    read_data = []
    for i in range(iter):
        read_data1 = send_and_receive_cbor(nkfido2_client, Command.GENERATE_RESIDENT_KEY)
        helper_view_dict(read_data1)
        assert check_keys_in_received_dictionary(read_data1, ["PUBKEY", "KEYHANDLE"])
        read_data.append(read_data1)

    for i in range(iter):
        read_data1 = read_data[i]
        data = {"KEYHANDLE": read_data1["KEYHANDLE"]}
        read_data2 = send_and_receive_cbor(nkfido2_client, Command.READ_RESIDENT_KEY_PUBLIC, data)
        helper_view_dict(read_data2)
        assert check_keys_in_received_dictionary(read_data2, ["PUBKEY", "KEYHANDLE"])

        assert read_data2["PUBKEY"] == read_data1["PUBKEY"]

    for i in range(iter):
        print(read_data[i]["PUBKEY"].hex())


def test_login(nkfido2_client: NKFido2Client):
    # send PIN and get TP for the FIDO U2F communication
    #   (without the ability to confirm the command with the regular FIDO2 PIN request)
    # WC < PIN
    # WC > TP
    s, data = send_and_receive(nkfido2_client, Command.SET_PIN, dict(PIN=Constants.PIN), check=False)
    data = {"PIN": Constants.PIN}
    read_data = send_and_receive_cbor(nkfido2_client, Command.LOGIN, data)
    helper_view_dict(read_data)
    assert check_keys_in_received_dictionary(read_data, ["TP"])
    STATE["TP"] = read_data["TP"]


def test_login_wrong(nkfido2_client: NKFido2Client):
    data = {"PIN": Constants.PIN_BAD}
    send_and_receive(nkfido2_client, Command.LOGIN, data, expected_error=ExecError.INVALID_PIN)


def test_login_wrong_attempt_counter(nkfido2_client: NKFido2Client):
    # Reset attempt counter
    send_and_receive(nkfido2_client, Command.FACTORY_RESET)
    helper_login(nkfido2_client, Constants.PIN)
    send_and_receive(nkfido2_client, Command.LOGOUT)

    data = {"PIN": Constants.PIN_BAD}
    for i in range(Constants.PIN_ATTEMPTS_COUNTER_DEFAULT_VALUE):
        send_and_receive(nkfido2_client, Command.LOGIN, data, expected_error=ExecError.INVALID_PIN)
        pin_attempts_counter = send_and_receive_cbor(nkfido2_client, Command.STATUS)['PIN_ATTEMPTS']
        assert Constants.PIN_ATTEMPTS_COUNTER_DEFAULT_VALUE-(i+1) == pin_attempts_counter
    send_and_receive(nkfido2_client, Command.LOGIN, data, expected_error=ExecError.ERR_NOT_ALLOWED)

    # Reset state, as this is the only way to unlock access now
    send_and_receive(nkfido2_client, Command.FACTORY_RESET)
    helper_login(nkfido2_client, Constants.PIN)
    send_and_receive(nkfido2_client, Command.LOGIN, data, expected_error=ExecError.INVALID_PIN)


def test_login2(nkfido2_client: NKFido2Client):
    # same as test_login, but checks if the generated tokens are different
    data = {"PIN": Constants.PIN}
    read_data2 = send_and_receive_cbor(nkfido2_client, Command.LOGIN, data)
    read_data = send_and_receive_cbor(nkfido2_client, Command.LOGIN, data)
    assert read_data["TP"] != read_data2["TP"]
    helper_view_dict(read_data)
    assert check_keys_in_received_dictionary(read_data, ["TP"])
    STATE["TP"] = read_data["TP"]

    helper_login(nkfido2_client, Constants.PIN)
    assert STATE["TP"] != read_data["TP"]


def test_logout(nkfido2_client: NKFido2Client):
    # check first if we are logged in
    helper_login(nkfido2_client, Constants.PIN)
    configuration_data = send_and_receive_cbor(nkfido2_client, Command.GET_CONFIGURATION)
    send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY)
    send_and_receive(nkfido2_client, Command.LOGOUT)

    # here test some TP requiring operation
    commands_requiring_session = [
        (Command.SET_CONFIGURATION, configuration_data),
        # (Command.GET_CONFIGURATION, None),
        (Command.INITIALIZE_SEED, None),
        (Command.RESTORE_FROM_SEED, {"MASTER": b"1" * 32, "SALT": b"2" * 8}),
        (Command.GENERATE_KEY, None),
        (Command.SIGN, {"HASH": b"placeholder", "KEYHANDLE": b"placeholder"}),
        (Command.DECRYPT,
         {"DATA": b"placeholder", "KEYHANDLE": b"placeholder", "HMAC": b"placeholder", "ECCEKEY": b"placeholder"}),

        (Command.GENERATE_KEY_FROM_DATA, {"HASH": b"p"*32}),
        (Command.GENERATE_RESIDENT_KEY, None),
        (Command.READ_RESIDENT_KEY_PUBLIC, {"KEYHANDLE": b"placeholder"}),
        (Command.DISCOVER_RESIDENT_KEYS, None),  # TODO correct input data once this command is implemented
        (Command.WRITE_RESIDENT_KEY, {"RAW_KEY_DATA": b"placeholder"}),
    ]
    for cmd, data in commands_requiring_session:
        send_and_receive(nkfido2_client, cmd, data=data, expected_error=ExecError.REQ_AUTH)


def test_factory_reset(nkfido2_client: NKFido2Client):
    # Setup. Make sure we are logged in, and we can call commands normally
    helper_login(nkfido2_client, Constants.PIN)
    send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY)
    data_key = {"HASH": sha256(b"test").digest()}
    read_data_initial = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data_key)
    rk_kh_init = send_and_receive_cbor(nkfido2_client, Command.GENERATE_RESIDENT_KEY)["KEYHANDLE"]
    send_and_receive_cbor(nkfido2_client, Command.READ_RESIDENT_KEY_PUBLIC, {"KEYHANDLE": rk_kh_init})

    # Execute operation to be tested
    send_and_receive(nkfido2_client, Command.FACTORY_RESET)

    # A. Session should be closed if open
    send_and_receive(nkfido2_client, Command.GENERATE_KEY, expected_error=ExecError.REQ_AUTH)

    # B. PIN should be removed. Change PIN should fail.
    data = {
        "PIN": Constants.PIN_BAD,
        "NEWPIN": Constants.PIN_BAD,
    }
    send_and_receive(nkfido2_client, Command.CHANGE_PIN, data, expected_error=ExecError.ERR_NOT_ALLOWED)

    send_and_receive(nkfido2_client, Command.SET_PIN, dict(PIN=Constants.PIN))
    helper_login(nkfido2_client, Constants.PIN)
    # C. All user data should be cleared
    # C1. Derived keys should be different from the same hash
    read_data_after_reset = send_and_receive_cbor(nkfido2_client, Command.GENERATE_KEY_FROM_DATA, data_key)
    assert read_data_after_reset["PUBKEY"] != read_data_initial["PUBKEY"]

    # C2. RK should not be available by keyhandle, or listed for the given origin
    # TODO to change ERR_MEMORY_FULL with ERR_FAILED_LOADING_DATA
    rk_pb = send_and_receive(nkfido2_client, Command.READ_RESIDENT_KEY_PUBLIC, {"KEYHANDLE": rk_kh_init},
                             expected_error=ExecError.ERR_MEMORY_FULL)


class UnreachableException(Exception):
    pass


def test_pin_set_wrong_length(nkfido2_client: NKFido2Client):
    data = {"PIN": Constants.PIN_SHORT}
    send_and_receive(nkfido2_client, Command.SET_PIN, data, expected_error=ExecError.ERR_NOT_ALLOWED)

    data = {"PIN": Constants.PIN_LONG}
    send_and_receive(nkfido2_client, Command.SET_PIN, data, expected_error=ExecError.ERR_BAD_FORMAT)


def test_pin_set(nkfido2_client: NKFido2Client):
    # condition: unset PIN (e.g. after a factory reset)
    # should fail due to not set PIN after the factory reset
    send_and_receive(nkfido2_client, Command.FACTORY_RESET)
    data = {"PIN": Constants.PIN}
    send_and_receive(nkfido2_client, Command.LOGIN, data, expected_error=ExecError.ERR_NOT_ALLOWED)
    data = {"PIN": Constants.PIN}
    send_and_receive(nkfido2_client, Command.SET_PIN, data)

    # test for invalid PIN check
    data = {"PIN": Constants.PIN_BAD}
    send_and_receive(nkfido2_client, Command.LOGIN, data, expected_error=ExecError.INVALID_PIN)

    # should work
    data = {"PIN": Constants.PIN}
    send_and_receive_cbor(nkfido2_client, Command.LOGIN, data)


def test_pin_change(nkfido2_client: NKFido2Client):
    # todo check session clearing after PIN change
    # todo DESIGN is TP required for the PIN change, or the current PIN suffices?

    # condition: PIN set
    # should fail
    data = {
        "PIN": Constants.PIN_BAD,
        "NEWPIN": Constants.PIN_BAD,
        }
    send_and_receive(nkfido2_client, Command.CHANGE_PIN, data, expected_error=ExecError.INVALID_PIN)

    # should pass
    data = {
        "PIN": Constants.PIN,
        "NEWPIN": Constants.PIN2,
    }
    send_and_receive(nkfido2_client, Command.CHANGE_PIN, data)

    # should fail, when tried the second time
    data = {
        "PIN": Constants.PIN,
        "NEWPIN": Constants.PIN2,
    }
    send_and_receive(nkfido2_client, Command.CHANGE_PIN, data, expected_error=ExecError.INVALID_PIN)

    # reverting the primary/default PIN back
    data = {
        "PIN": Constants.PIN2,
        "NEWPIN": Constants.PIN,
    }
    send_and_receive(nkfido2_client, Command.CHANGE_PIN, data)

    # reverting the primary/default PIN back should fail the second time
    data = {
        "PIN": Constants.PIN2,
        "NEWPIN": Constants.PIN,
    }
    send_and_receive(nkfido2_client, Command.CHANGE_PIN, data, expected_error=ExecError.INVALID_PIN)



def test_configure(nkfido2_client: NKFido2Client):
    """
    Get the current data
    change it
    get the current data and compare to previous one
    WC <> CONFIRMATION
    """
    # simple read/write test
    helper_login(nkfido2_client, Constants.PIN)

    data = send_and_receive_cbor(nkfido2_client, Command.GET_CONFIGURATION)
    send_and_receive(nkfido2_client, Command.SET_CONFIGURATION, data)
    read_data = send_and_receive_cbor(nkfido2_client, Command.GET_CONFIGURATION)
    assert read_data == data

    # change one of the options
    data['CONFIRMATION'] += 1
    send_and_receive(nkfido2_client, Command.SET_CONFIGURATION, data)
    read_data = send_and_receive_cbor(nkfido2_client, Command.GET_CONFIGURATION)
    assert read_data == data

