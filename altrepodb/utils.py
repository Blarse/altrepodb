# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021 BaseALT Ltd
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

import os
import re
import json
import lzma
import mmh3
import logging
import argparse
import datetime
import threading
import subprocess
from time import time
from dateutil import tz
from pathlib import Path
from functools import wraps
from logging import handlers
from hashlib import sha1, sha256, md5, blake2b
from typing import Any, Iterable, Union, Hashable, Optional

from altrpm import rpm
from .logger import LoggerProtocol, FakeLogger, _LoggerOptional
from .exceptions import RunCommandError

# custom types
_FileName = Union[str, os.PathLike]


DEFAULT_LOGGER = FakeLogger


def mmhash(val: Any) -> int:
    """Calculate MurmurHash3 64-bit value."""

    a, b = mmh3.hash64(val, signed=False)
    return a ^ b


def _snowflake_id(timestamp: int, lower_32bit: int, epoch: int) -> int:
    """Snowflake-like ID generation base function.
    Returns Returns 64 bit wide unsigned integer:
        - most significant 32 bits timestamp time delta from epoch
        - less significant 32 bits from 'lower_32bits' argument
    """
    sf_ts = timestamp - epoch
    sf_id = (sf_ts << 32) | (lower_32bit & 0xFFFFFFFF)
    return sf_id


def snowflake_id_pkg(hdr: dict, epoch: int = 1_000_000_000) -> int:
    """Genarates showflake-like ID using data from RPM package header object.
    Returns 64 bit wide unsigned integer:
        - most significant 32 bits package build time delta from epoch
        - less significant 32 bits are mutmurHash from package sign header (SHA1 + MD5 + GPG)

    Args:
        hdr (dict): RPM package header object
        epoch (int, optional): Base epoch for timestamp part calculation. Defaults to 1_000_000_000.

    Returns:
        int: showflake like ID
    """

    buildtime: int = cvt(hdr[rpm.RPMTAG_BUILDTIME], int)  # type: ignore
    sha1: bytes = bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER]))  # type: ignore
    md5: bytes = hdr[rpm.RPMTAG_SIGMD5]  # bytes
    gpg: bytes = hdr[rpm.RPMTAG_SIGGPG]  # bytes

    if md5 is None:
        md5 = b""
    if gpg is None:
        gpg = b""
    # combine multiple GPG signs in one
    if isinstance(gpg, list):
        gpg_ = b""
        for k in gpg:
            gpg_ += k  # type: ignore
        gpg = gpg_

    data = sha1 + md5 + gpg
    sf_hash = mmh3.hash(data, signed=False)
    return _snowflake_id(timestamp=buildtime, lower_32bit=sf_hash, epoch=epoch)


def snowflake_id_sqfs(
    mtime: int, sha1: bytes, size: int, epoch: int = 1_000_000_000
) -> int:
    """Generates snowflake-like ID for SquashFS image identification."""

    data = (
        sha1
        + (mtime).to_bytes((mtime.bit_length() + 7) // 8, byteorder="little")
        + (size).to_bytes((size.bit_length() + 7) // 8, byteorder="little")
    )
    sf_hash = mmh3.hash(data, signed=False) & 0xFFFFFFFF

    return _snowflake_id(timestamp=mtime, lower_32bit=sf_hash, epoch=epoch)


def detect_arch(hdr):
    """Converts package architecture from header."""

    package_name = cvt(hdr[rpm.RPMTAG_NAME])
    if package_name.startswith("i586-"):
        return "x86_64-i586"
    return cvt(hdr[rpm.RPMTAG_ARCH])


def valid_date(s: str) -> datetime.datetime:
    """Convert string to datetime object or rise an error."""

    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)


def valid_version(version: str) -> tuple[int, int, int]:
    """Split version string to tuple (major, minor, sub)."""

    try:
        major_ = minor_ = sub_ = 0
        s = version.strip().split(".")
        major_ = int(s[0])

        if len(s) >= 2:
            minor_ = int(s[1])
        if len(s) == 3:
            sub_ = int(s[2])
        if len(s) > 3:
            raise ValueError

        return major_, minor_, sub_
    except ValueError:
        msg = "Failed to parse version: '{0}'.".format(version)
        raise argparse.ArgumentTypeError(msg)


def valid_url(url: str) -> str:
    """Check if string is valid URL."""

    url_match = re.compile(
        "((([A-Za-z]{3,9}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w\-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)"  # type: ignore
    )
    if not url_match.search(url):
        raise argparse.ArgumentTypeError("Not a valid URL")
    return url


def check_package_in_cache(cache: Iterable, pkghash: Any) -> Union[Any, None]:
    """Check whether the hash is in the cache."""

    if pkghash in cache:
        return pkghash
    return None


def get_logger(
    name: str, tag: str = "", date: Union[datetime.date, None] = None
) -> LoggerProtocol:
    """Create and configure logger."""

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if date is None:
        date = datetime.date.today()
    file_handler = handlers.RotatingFileHandler(
        filename="{0}-{1}-{2}.log".format(name, tag, date.strftime("%Y-%m-%d")),
        maxBytes=2 ** 26,
        backupCount=10,
    )
    fmt = logging.Formatter(
        "%(asctime)s\t%(levelname)s\t%(threadName)s\t%(funcName)s\t%(lineno)d\t%(message)s"
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s\t%(message)s"))
    stream_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


class Display:
    MSG = "Processed {0} packages in {1:.3f} sec. {2:.3f} sec. per package on average."

    """Show information about progress."""

    def __init__(
        self, log: LoggerProtocol, timer_init_delta: float = 0, step: int = 1000
    ):
        self.lock = threading.Lock()
        self.log = log
        self.counter = 0
        self.timer = None
        self.step = step
        self.timesum = 0
        self.timer_short = None
        self.timesum_short = 0
        self.timer_init_delta = timer_init_delta

    def _showmsg(self):
        t = time() - self.timer  # type: ignore
        self.log.info(self.MSG.format(self.step, t, t / self.step))
        self.log.info("Total: {0}".format(self.counter))

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
        self.log.info(
            self.MSG.format(
                self.counter,
                self.timesum,
                self.timesum / (self.counter if self.counter else 1),
            )
        )


class Timing:
    timing = False

    @classmethod
    def timeit(cls, logger_name):
        def timer(f):
            """Measuring execution time."""
            log = logging.getLogger(logger_name)

            @wraps(f)
            def wrap(*args, **kw):
                ts = time()
                result = f(*args, **kw)
                te = time()
                if cls.timing:
                    log.debug("F:{0} T:{1:.5f}".format(f.__name__, te - ts))
                return result

            return wrap

        return timer


def cvt(b: Any, t: type = str) -> Any:
    """Convert byte string or list of byte strings to strings or list strings.
    Return default vaues for bytes, string and int if input value is None."""

    if isinstance(b, bytes) and t is str:
        return b.decode("latin-1")
    if isinstance(b, list):
        return [cvt(i) for i in b]
    if b is None:
        if t is bytes:
            return b""
        if t is str:
            return ""
        if t is int:
            return 0
    return b


def cvt_ts(ts: Union[int, list[int]]) -> Any:
    """Convert timestamp or list of timestamps to datetime object or list
    of datetime objects."""

    if isinstance(ts, int):
        return datetime.datetime.fromtimestamp(ts)
    if isinstance(ts, list):
        return [cvt_ts(i) for i in ts]
    return ts


def changelog_to_list(dates: list, names: list, texts: list) -> list:
    """Compile changelog records to dict of elements."""

    if not len(dates) == len(names) == len(texts):
        raise ValueError
    chlog = []
    for date_, name_, text_ in zip(dates, names, texts):
        tmp = cvt(name_)
        if len(tmp.split(">")) == 2:  # type: ignore
            name = tmp.split(">")[0] + ">"  # type: ignore
            evr = tmp.split(">")[1].strip()  # type: ignore
        else:
            name = tmp
            evr = ""
        chlog.append((int(date_), name, evr, cvt(text_), mmhash(cvt(text_))))
    return chlog


def convert_file_class(fc: str) -> str:
    """Converts file class value from RPM header to CH Enum."""

    lut = {
        "directory": "directory",
        "symbolic link to": "symlink",
        "socket": "socket",
        "character special": "char",
        "block special": "block",
        "fifo (named pipe)": "fifo",
        "file": "file",
    }
    if fc == "":
        return lut["file"]
    else:
        for k, v in lut.items():
            if fc.startswith(k):
                return v
    return ""


# packager parsing regex
packager_pattern = re.compile("\W?([\w\-\@'. ]+?)\W? (\W.+?\W )?<(.+?)>")  # type: ignore


def packager_parse(packager: str) -> Union[tuple[str, str], None]:
    """Parse packager for name and email."""

    m = packager_pattern.search(packager)
    if m is not None:
        name_ = m.group(1).strip()
        email_ = m.group(3).strip().replace(" at ", "@")
        return name_, email_
    return None


def sha1_from_file(
    fname: _FileName, as_bytes: bool = False, capitalized: bool = False
) -> Union[bytes, str]:
    """Calculates SHA1 hash from file."""

    hash = sha1()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    if as_bytes:
        return hash.digest()
    if capitalized:
        return hash.hexdigest().upper()
    else:
        return hash.hexdigest()


def sha256_from_file(
    fname: _FileName, as_bytes: bool = False, capitalized: bool = False
) -> Union[bytes, str]:
    """Calculates SHA256 hash from file."""

    hash = sha256()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    if as_bytes:
        return hash.digest()
    if capitalized:
        return hash.hexdigest().upper()
    else:
        return hash.hexdigest()


def md5_from_file(
    fname: _FileName, as_bytes: bool = False, capitalized: bool = False
) -> Union[bytes, str]:
    """Calculates MD5 hash from file."""

    hash = md5()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    if as_bytes:
        return hash.digest()
    if capitalized:
        return hash.hexdigest().upper()
    else:
        return hash.hexdigest()


def blake2b_from_file(
    fname: _FileName, as_bytes: bool = False, capitalized: bool = False
) -> Union[bytes, str]:
    """Calculates blake2b hash from file."""

    hash = blake2b()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    if as_bytes:
        return hash.digest()
    if capitalized:
        return hash.hexdigest().upper()
    else:
        return hash.hexdigest()


def hashes_from_file(fname: _FileName) -> tuple[bytes, bytes, bytes]:
    """Calculates md5, sha256 and blake2b hashes from file."""

    md5_h = md5()
    sha256_h = sha256()
    blake2b_h = blake2b()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            md5_h.update(byte_block)
            sha256_h.update(byte_block)
            blake2b_h.update(byte_block)

    return md5_h.digest(), sha256_h.digest(), blake2b_h.digest()


def checksums_from_file(fname: _FileName) -> tuple[str, str, str]:
    """Calculates MD5, SHA256 and GOST12 hashes from file."""

    CHUNK_SIZE = 16384  # read file by 16 kB chunks
    md5_h = md5()
    sha256_h = sha256()

    try:
        gost12_h = subprocess.Popen(
                "gost12sum",
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
        with open(fname, "rb") as f:
            for byte_block in iter(lambda: f.read(CHUNK_SIZE), b""):
                md5_h.update(byte_block)
                sha256_h.update(byte_block)
                gost12_h.stdin.write(byte_block)  # type: ignore

        res, _ = gost12_h.communicate()
        if gost12_h.returncode != 0:
            raise RunCommandError("Subprocess 'gost12sum' returned non zero code")
    except Exception as e:
        gost12_h.kill()  # type: ignore
        gost12_h.wait(timeout=10)  # type: ignore
        raise e

    gost12_hexdigest = res.decode("utf-8").split(" ")[0]

    return md5_h.hexdigest(), sha256_h.hexdigest(), gost12_hexdigest


def join_dicts_with_as_string(
    d1: dict, d2: Union[dict, list, tuple, str], key: Hashable
) -> dict:
    """Join dictionary with dictionary, list, tuple or any object
    that can be represented as string.
    Stringify all elements of joined object if it is not dictionary.
    Do not preserve value in original dictionary if given 'key' exists.
    If joined object is not dictionary and key is None returns original dictionary."""

    res = d1
    if not isinstance(d1, dict):
        return d1
    if isinstance(d2, dict):
        res.update(d2)
        # return res
    elif isinstance(d2, list) or isinstance(d2, tuple):
        if key is None:
            return d1
        res.update({key: ", ".join([str(v) for v in d2])})
    else:
        if key is None:
            return d1
        res.update({key: str(d2)})
    return res


def cvt_ts_to_datetime(
    ts: Union[int, float], use_local_tz: bool = False
) -> datetime.datetime:
    """Converts timestamp to datetime object as UTC or local time."""

    utc = datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=tz.tzutc())
    if use_local_tz:
        return utc.astimezone(tz.tzlocal())
    else:
        return utc


def cvt_datetime_local_to_utc(dt: datetime.datetime) -> datetime.datetime:
    """Converts timezone from local to UTC."""

    dt = dt.replace(tzinfo=tz.tzlocal())
    return dt.astimezone(tz.tzutc())


def set_datetime_timezone_to_utc(dt: datetime.datetime) -> datetime.datetime:
    """Set timezone to UTC."""

    return dt.replace(tzinfo=tz.tzutc())


def val_from_json_str(json_str: str, val_key: str) -> Any:
    """Returns value from stringified JSON by key."""

    if json_str is None or json_str == "":
        return None
    else:
        try:
            json_dict = json.loads(json_str)
            if val_key in json_dict:
                return json_dict[val_key]
            else:
                return None
        except json.JSONDecodeError:
            return None


def unxz(fname: _FileName, mode_binary: bool = False) -> Union[bytes, str]:
    """Reads '.xz' compressed file contents."""

    if mode_binary:
        with lzma.open(fname, "rb") as f:
            res = f.read()
        return res
    else:
        with lzma.open(fname, "rt") as f:
            res = f.read()
        return res


def run_command(
    *args,
    env: Optional[dict[str, str]] = None,
    raise_on_error: bool = False,
    logger: _LoggerOptional = None,
    timeout: Optional[float] = None,
) -> tuple[str, str, str, int]:
    """Run command from args. Raises exception if rsubprocess returns non zero code."""

    if logger is None:
        logger = DEFAULT_LOGGER(name="run_command")
    cmdline = " ".join([*args])
    logger.debug(f"Run command: {cmdline}")
    try:
        env_ = env if env is not None else os.environ.copy()
        sub = subprocess.run(
            [*args],
            env=env_,
            capture_output=True,
            text=True,
            check=raise_on_error,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"subprocess commandline: {e.cmd} returned {e.returncode}")
        logger.error(f"subprocess stdout: {e.stdout}")
        logger.error(f"subprocess stderr: {e.stderr}")
        raise RunCommandError("Subprocess returned non zero code") from e
    except subprocess.TimeoutExpired as e:
        logger.error(
            f"subprocess commandline: {e.cmd}, {timeout} seconds timeout expired"
        )
        raise RunCommandError("Subprocess has timed out") from e
    return cmdline, sub.stdout, sub.stderr, sub.returncode


def dump_to_json(object: Any, file: _FileName) -> None:
    """Dumps object to JSON file in current directory."""

    f = Path.joinpath(Path.cwd(), file)
    f.write_text(json.dumps(object, indent=2, sort_keys=True, default=str))


def bytes2human(size: Union[int, float]) -> str:
    """Convert file size in bytes to human readable string representation."""

    for unit in ["", "K", "M", "G", "T", "P", "E"]:
        if abs(size) < 1024.0:
            return f"{size:3.1f} {unit}B"
        size /= 1024.0
    return f"{size:.1f} ZB"
