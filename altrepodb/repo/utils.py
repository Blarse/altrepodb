# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021-2022 BaseALT Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import re
import mmh3
import logging
from time import time
from datetime import datetime
from threading import Lock
from typing import Any, Hashable, Optional, Union


class Display:
    MSG = "Processed {0} packages in {1:.3f} sec. {2:.3f} sec. per package on average."

    """Show information about progress."""

    def __init__(
        self, logger: Optional[logging.Logger] = None, timer_init_delta: float = 0, step: int = 1000
    ):
        self.lock = Lock()
        self.counter = 0
        self.timer = None
        self.step = step
        self.timesum = 0
        self.timer_short = None
        self.timesum_short = 0
        self.timer_init_delta = timer_init_delta
        if logger is None:
            self.logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        else:
            self.logger = logger

    def _showmsg(self):
        t = time() - self.timer  # type: ignore
        self.logger.info(self.MSG.format(self.step, t, t / self.step))
        self.logger.info("Total: {0}".format(self.counter))

    def _update(self):
        self.counter += 1
        t = time()
        self.timesum_short += t - self.timer_short  # type: ignore
        self.timer_short = time()
        if self.counter % self.step == 0:
            self._showmsg()
            t = time()
            self.timesum += t - self.timer  # type: ignore
            self.timer = time()

    def inc(self):
        with self.lock:
            if self.timer is None:
                self.timer = time()
                self.timer_short = time()
            self._update()

    def conclusion(self):
        if self.timesum_short > self.timesum:
            self.timesum = self.timesum_short
        self.timesum += self.timer_init_delta
        self.logger.info(
            self.MSG.format(
                self.counter,
                self.timesum,
                self.timesum / (self.counter if self.counter else 1),
            )
        )


def mmhash(val: Any) -> int:
    """Calculate MurmurHash3 64-bit value."""

    a, b = mmh3.hash64(val, signed=False)
    return a ^ b


def snowflake_id(timestamp: int, lower_32bit: int, epoch: int) -> int:
    """Snowflake-like ID generation base function.
    Returns Returns 64 bit wide unsigned integer:
        - most significant 32 bits timestamp time delta from epoch
        - less significant 32 bits from 'lower_32bits' argument
    """
    sf_ts = timestamp - epoch
    sf_id = (sf_ts << 32) | (lower_32bit & 0xFFFFFFFF)
    return sf_id


def update_dictionary_with(
    base_dict: dict[Any, Any],
    value: Union[dict[Any, Any], list[Any], tuple[Any], str],
    key: Hashable,
) -> dict[Any, Any]:
    """Updates dictionary with dictionary, list, tuple or any object
    that can be represented as string.
    Stringify all elements of joined object if it is not dictionary.
    Do not preserve value in original dictionary if given 'key' exists.
    If joined object is not dictionary and key is None returns original dictionary."""

    result = base_dict
    if not isinstance(base_dict, dict):
        return base_dict
    if isinstance(value, dict):
        result.update(value)
    elif isinstance(value, list) or isinstance(value, tuple):
        if key is None:
            return base_dict
        result.update({key: ", ".join([str(v) for v in value])})
    else:
        if key is None:
            return base_dict
        result.update({key: str(value)})
    return result


def convert(value: Any, value_type: type = str) -> Any:
    """Convert byte string or list of byte strings to strings or list strings.
    Other types returned as is without conversion.
    Return default vaues for bytes, string and int if input value is None."""

    if isinstance(value, bytes) and value_type is str:
        return value.decode("latin-1")
    if isinstance(value, list):
        return [convert(i) for i in value]
    if value is None:
        if value_type is bytes:
            return b""
        if value_type is str:
            return ""
        if value_type is int:
            return 0
    return value


def convert_timestamp(ts: Union[int, list[int]]) -> Any:
    """Convert timestamp or list of timestamps to datetime object or list
    of datetime objects."""

    if isinstance(ts, int):
        return datetime.fromtimestamp(ts)
    if isinstance(ts, list):
        return [convert_timestamp(i) for i in ts]
    return ts


packager_pattern = re.compile(r"\W?([\w\-\@'. ]+?)\W? (\W.+?\W )?<(.+?)>")


def parse_packager(packager: str) -> Union[tuple[str, str], None]:
    """Parse packager for name and email with regex."""

    m = packager_pattern.search(packager)
    if m is not None:
        name_ = m.group(1).strip()
        email_ = m.group(3).strip().replace(" at ", "@")
        return name_, email_
    return None
