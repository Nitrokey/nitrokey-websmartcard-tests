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
import dataclasses
import struct
import sys
from collections import Counter
from math import ceil
from time import sleep, time
from typing import Tuple, List

from fido2.ctap import CtapError
from pynitrokey.fido2.client import NKFido2Client as NKFido2Client
from pynitrokey.fido2.commands import SoloBootloader

from webcrypt.helpers import cbor_dumps, cbor_loads
from webcrypt.llog import log
from webcrypt.types import CmdTrans, CommCommands, Command, ExecError

print_packet_debug_info = True

temporary_password = [b'']

APPID = b"A" * 32
APPID2 = b"B" * 32


def set_global_appid(new_app_id: bytes):
    global APPID
    assert len(new_app_id) <= 32
    APPID = new_app_id.zfill(32)


def set_temporary_password(password: bytes):
    temporary_password.append(password)
    my_print(f'Setting TMP AUTH TOKEN to {password.hex()}')


def get_tmp():
    return temporary_password[-1]


def send_and_receive(nkfido2_client: NKFido2Client, command: Command, data=None, expected_success: bool = True,
                     check: bool = True, expected_error: ExecError = None) -> Tuple[
    bool, bytes]:
    if data is None:
        data = {}
    import copy
    data = copy.deepcopy(data)

    if expected_error:
        expected_success = False

    for k,v in data.items():
        if isinstance(v, str):
            raise RuntimeError(f'{k} is a str!')

    log.info(f'Sending data: {data}')

    execution_success = None
    last_err = None
    start = time()
    MAX_CONFIRMATION_TIME = 30
    while time() - start < MAX_CONFIRMATION_TIME:
        execution_success, err_codes = device_send(nkfido2_client, data, command)
        last_err = err_codes[-1]
        if last_err != ExecError.ERR_USER_NOT_PRESENT.value[0]:
            break
        my_print(f'Please confirm the action for command: {command}')
        sys.stdout.flush()
        sys.stderr.flush()
        sleep(1)

    if check:
        assert execution_success == expected_success
        if expected_error:
            assert last_err == expected_error.value[0]

    if not execution_success:
        return execution_success, b''
    command_received, read_data_bytes = device_receive(nkfido2_client)
    assert command_received == command.value[0]
    return execution_success, read_data_bytes


def device_receive(nkfido2_client: NKFido2Client, appid=APPID) -> Tuple[int, bytes]:
    size = 1024  # should be set to maximum value in the output buffer
    data_received = []
    chunk_size = 69
    packets_count = int(ceil(size / chunk_size))
    my_print(f'Receiving {size} bytes')
    for packet, i in enumerate(range(0, size, chunk_size)):
        if i - 2 > size:  # FIXME set the correct breaking condition
            break
        cmd_obj = CmdTrans(packets_count=packets_count, packet_num=packet, data=b'', this_chunk_length=chunk_size,
                         chunk_size=chunk_size, command_id=CommCommands.READ.value)
        cmd = cmd_obj.construct()
        res = []
        try:
            res = webcrypt_exchange(nkfido2_client, cmd, appid=appid)
        except Exception as e:
            my_print(f'Exception while receiving: {e}')
            break

        if not data_received:
            # Parsing to print debug data only
            size = int.from_bytes(res[0:2], 'big')
            my_print(f'Received size from the first packet: {res[0:2].hex()} -> {size}')

        data_received.append(res)
        if print_packet_debug_info:
            my_print(f'Packet info: {len(cmd)} {packet}/{packets_count} {chunk_size} {size} {cmd}')
            my_print(f'Received packet with partial data: {res.hex()}')

    data_received = b''.join(data_received)
    if print_packet_debug_info:
        my_print(f'All data received: {Counter(data_received).most_common(10)}')
        my_print(f'All data received: {data_received.hex()}')
        try:
            my_print(f'All data received CBOR: {cbor_loads(data_received[3:])}')
        except Exception:
            pass

    r = ReceivedData.parse(data_received)
    return r.command_id, r.data


@dataclasses.dataclass
class ReceivedData:
    command_id: int
    data: bytes
    size: int

    @classmethod
    def parse(cls, data_received):
        # packet size (2) = N+2+1, command id (1), data(N)
        rec = ReceivedData(command_id=data_received[2], data=data_received[3:],
                            size=int.from_bytes(data_received[0:2], 'big'))
        return rec


WalletWebcrypt = 0x22


def format_request(cmd, addr=0, data=b"A" * 16):
    if cmd == WalletWebcrypt:
        cmd = struct.pack("B", cmd)
        return cmd + SoloBootloader.TAG + data
    raise NotImplemented('Invalid command')


def exchange_u2f(nkfido2_client, cmd, data):
    req = format_request(cmd, data=data)

    appid = b'A' * 32
    chal = b'B' * 32
    res = nkfido2_client.ctap1.authenticate(chal, appid, req)
    print(f"Received CTAP1 signature raw: {res.signature.hex()}")
    assert len(res.signature) >= 1
    return res.signature


def exchange_fido2(nkfido2_client, cmd, data):
    req = format_request(cmd, data=data)

    appid = 'example.org'
    chal = b'B' * 32

    assertion = nkfido2_client.ctap2.get_assertion(
        appid, chal, [{"id": req, "type": "public-key"}]
    )

    res = assertion
    return res.signature


UDPSERVER = None

def exchange_UDP_direct(data=b''):
    global UDPSERVER
    from webcrypt.HIDoverUDP import HidOverUDP
    if UDPSERVER is None:
        UDPSERVER = HidOverUDP("127.0.0.1:8111")
        UDPSERVER.sock.settimeout(1000*1000.0)
    data = format_request(WalletWebcrypt, data=data)
    UDPSERVER.Write(data)
    res = UDPSERVER.Read()
    return res


def webcrypt_exchange(nkfido2_client: NKFido2Client, data=b'', appid=b"A" * 32):
    res = None
    import os
    env_transport = os.getenv("TRANSPORT")
    if not os.getenv("REAL_HARDWARE") or env_transport == "UDP":
        print('Selecting exchange_UDP_direct')
        res = exchange_UDP_direct(data=data)
    elif env_transport == "FIDO2":
        print('Selecting exchange_fido2')
        res = exchange_fido2(nkfido2_client, cmd=WalletWebcrypt, data=data)
    else:
        print('Selecting exchange_u2f')
        res = exchange_u2f(nkfido2_client, WalletWebcrypt, data=data)
    return res


def device_send(nkfido2_client: NKFido2Client, data: dict, command: Command, appid=APPID) -> Tuple[bool, List[int]]:
    """
    Returns True on sending success (=all packets are confirmed to be received)
    """
    TEMP_PASS_KEY = 'TP'
    import copy
    data = copy.deepcopy(data)
    results: List = []
    if isinstance(data, dict):
        if TEMP_PASS_KEY not in data and command != Command.TEST_PING:
            data[TEMP_PASS_KEY] = get_tmp()
        if TEMP_PASS_KEY in data:
            my_print(f'Sending command with temp auth token={data[TEMP_PASS_KEY].hex()}')
    d: bytes = cbor_dumps(data)
    my_print(f'Sending data={d.hex()}')
    my_print(f'Sending data={bytes(d)}')

    chunk_size = 240 - CmdTrans.overhead_bytes_count()
    data = struct.pack("<H", len(d)) + command.as_bytes() + d
    # data = command.as_bytes() + d
    my_print(f"Send {command}")
    if print_packet_debug_info:
        my_print(f'CBOR encoded data dict (to send): ({len(data)}) {d.hex()}')
    packets_count = int(ceil(len(data) / chunk_size))
    for packet, i in enumerate(range(0, len(data), chunk_size)):
        data_to_send = data[i:i + chunk_size]
        assert len(data_to_send) <= chunk_size
        cmd = CmdTrans(packets_count=packets_count, packet_num=packet, data=data_to_send,
                       chunk_size=chunk_size, this_chunk_length=len(data_to_send),
                       command_id=CommCommands.WRITE.value)
        data_to_send = cmd.construct()
        if print_packet_debug_info:
            my_print(f'{len(data)} {packet}/{packets_count} {chunk_size} {len(data_to_send)} {data_to_send.hex()}')
        res = webcrypt_exchange(nkfido2_client, data_to_send, appid=appid)
        if print_packet_debug_info:
            my_print(f"Send result: {res.hex()}")
        # results.append(res[:1])
        results.append(int.from_bytes(res[:1], 'little'))
    success = True
    for s in results:
        err_code = s
        if err_code != 0:
            success = False
        for c in ExecError:
            if c.value[0] == err_code:
                my_print(f"Result {command}: {c}")
                break
    my_print(f"Send results: {results} {success}")
    return success, results


# my_print = log.info
# my_print = print
def my_print(x):
    print(x, file=sys.stderr)

oldprint = None


def set_debug_messages(a: int):
    global oldprint
    global my_print
    if oldprint is None:
        oldprint = my_print

    if a == 0:
        my_print = lambda x: x
    elif a == 1:
        my_print = oldprint
