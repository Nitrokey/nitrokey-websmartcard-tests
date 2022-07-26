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
import logging
from functools import lru_cache
from sys import stderr

LOG_FORMAT = '* %(levelname)s %(relativeCreated)6dms %(filename)s:%(lineno)d %(message)s'


@lru_cache
def get_logger():
    # logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, stream=stderr)
    llog = logging.getLogger('webcrypt')
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(LOG_FORMAT)
    ch.setFormatter(formatter)
    llog.addHandler(ch)
    return llog

log = get_logger()


def log_data(x):
    log.debug(x)
