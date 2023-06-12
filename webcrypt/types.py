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
import struct
from enum import Enum

from attr import dataclass


class CommCommands(Enum):
    WRITE = 0x01  # send command
    READ = 0x02  # receive result


@dataclass
class CmdTrans:
    header = b'\xFF' * 14
    command_id: int
    packets_count: int
    packet_num: int
    chunk_size: int
    this_chunk_length: int
    data: bytes

    def wrap(self, data: int) -> bytes:
        return struct.pack("B", data)

    def construct(self) -> bytes:
        return b'' \
               + self.wrap(self.command_id) \
               + self.wrap(self.packet_num) \
               + self.wrap(self.packets_count) \
               + self.wrap(self.chunk_size) \
               + self.wrap(self.this_chunk_length) \
               + self.data

    @staticmethod
    def overhead_bytes_count() -> int:
        return 1 + 1 + 1 + 1 + 1 + len(CmdTrans.header)


class Command(Enum):
    STATUS = 0x00
    TEST_PING = 0x01
    TEST_CLEAR = 0x02
    TEST_REBOOT = 0x03
    LOGIN = 0x04
    LOGOUT = 0x05
    FACTORY_RESET = 0x06
    # deprecated
    PIN_ATTEMPTS = 0x07
    SET_CONFIGURATION = 0x08
    GET_CONFIGURATION = 0x09
    SET_PIN = 0x0A
    CHANGE_PIN = 0x0B

    INITIALIZE_SEED = 0x10
    RESTORE_FROM_SEED = 0x11
    GENERATE_KEY = 0x12
    SIGN = 0x13
    DECRYPT = 0x14
    GENERATE_KEY_FROM_DATA = 0x15
    GENERATE_RESIDENT_KEY = 0x16
    READ_RESIDENT_KEY_PUBLIC = 0x17
    DISCOVER_RESIDENT_KEYS = 0x18
    WRITE_RESIDENT_KEY = 0x19

    def as_bytes(self):
        return struct.pack("B", self.value)


class ExecError(Enum):
    SUCCESS = 0x00
    CTAP2_ERR_CBOR_PARSING = 0x10
    TooLongRequest = 0xE0
    REQ_AUTH = 0xF0
    INVALID_PIN = 0xF1
    ERR_NOT_ALLOWED = 0xF2
    ERR_BAD_FORMAT = 0xF3
    ERR_USER_NOT_PRESENT = 0xF4
    ERR_FAILED_LOADING_DATA = 0xF5
    ERR_INVALID_CHECKSUM = 0xF6
    ERR_ALREADY_IN_DATABASE = 0xF7
    ERR_NOT_FOUND = 0xF8
    ERR_ASSERT_FAILED = 0xF9
    ERR_INTERNAL_ERROR = 0xFA
    ERR_MEMORY_FULL = 0xFB
    ERR_NOT_IMPLEMENTED = 0xFC
    ERR_BAD_ORIGIN = 0xFD
    ERR_NOT_SET = 0xFE
    ERR_INVALID_COMMAND = 0xFF

    @classmethod
    def from_byte(cls, b:bytes) -> 'ExecError':
        for c in ExecError:
            if c.value == b:
                return c
        raise ValueError(f"Invalid attribute byte {b} / {b:02x}")
