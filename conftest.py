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

import os
import pytest
pytest.register_assert_rewrite("webcrypt.helpers")
pytest.register_assert_rewrite("webcrypt.communication")

from pynitrokey.fido2.client import NKFido2Client as NKFido2Client

from webcrypt.helpers import log_data

REAL_HARDWARE = False

class Constants:
    PIN = b"12345678"  # the default PIN
    PIN2 = b"this is new PIN"
    PIN_BAD = b'BAD PIN'
    PIN_SHORT = b'aa'
    PIN_LONG = b'a'*65
    PIN_ATTEMPTS_COUNTER_DEFAULT_VALUE = 8

def pytest_addoption(parser):
    parser.addoption(
        "--hardware", action="store_true", help="Run test on hardware"
    )


@pytest.fixture
def run_on_hardware(request):
    global REAL_HARDWARE
    REAL_HARDWARE = request.config.getoption("--hardware")
    return REAL_HARDWARE


@pytest.fixture(scope='session')
def nkfido2_client(request) -> NKFido2Client:
    import pynitrokey
    nkfido2_client = pynitrokey.fido2.client.NKFido2Client()

    REAL_HARDWARE = request.config.getoption("--hardware")
    if not REAL_HARDWARE:
        print('Forcing UDP')
        # pynitrokey.fido2.force_udp_backend()
    else:
        print('Selecting hardware')
        nkfido2_client.find_device()
        nkfido2_client.use_u2f()
    log_data(f'\nExchange selected: {nkfido2_client.exchange}\n')
    return nkfido2_client


TEST_DATA_SMALL = dict(ww=b'ww', a=b'A' * 5)
TEST_DATA = dict(ww=b'ww', xx=b'xx', cc=b'cc')


@pytest.fixture
def test_data() -> dict:
    return TEST_DATA


def fixture_data_medium() -> dict:
    t = TEST_DATA.copy()
    t['Key111'] = b'A' * 100
    return t


def fixture_data_big() -> dict:
    t = TEST_DATA.copy()
    t['Key111'] = b'A' * 300
    t['Key222'] = b'B' * 300
    return t


def fixture_data_random() -> dict:
    t = TEST_DATA.copy()
    t['Key111'] = os.urandom(150)
    t['Key222'] = os.urandom(150)
    t['xxx'] = os.urandom(30)
    return t

