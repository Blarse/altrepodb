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

import logging
import os
import re
import json
import lzma
import mmh3
import argparse
import datetime
import subprocess
from dateutil import tz
from pathlib import Path
from hashlib import sha1, sha256, md5, blake2b
from typing import Any, Iterable, Union, Optional

from .base import StringOrPath
from .logger import LoggerOptional
from .exceptions import RunCommandError


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
        r"((([A-Za-z]{3,9}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w\-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)"  # type: ignore
    )
    if not url_match.search(url):
        raise argparse.ArgumentTypeError("Not a valid URL")
    return url


def check_package_in_cache(cache: Iterable, pkghash: Any) -> Union[Any, None]:
    """Check whether the hash is in the cache."""

    if pkghash in cache:
        return pkghash
    return None


def sha1_from_file(fname: StringOrPath) -> bytes:
    """Calculates SHA1 hash from file."""

    hash = sha1()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    return hash.digest()


def sha256_from_file(fname: StringOrPath) -> bytes:
    """Calculates SHA256 hash from file."""

    hash = sha256()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    return hash.digest()


def md5_from_file(fname: StringOrPath) -> bytes:
    """Calculates MD5 hash from file."""

    hash = md5()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    return hash.digest()


def blake2b_from_file(fname: StringOrPath) -> bytes:
    """Calculates blake2b hash from file."""

    hash = blake2b()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            hash.update(byte_block)
    return hash.digest()


def calculate_sha256_blake2b(
    fname: StringOrPath,
    sha256_in: Optional[bytes],
    blake2b_in: Optional[bytes],
    en_blake2b: bool,
) -> tuple[bytes, bytes]:
    """Calculates SAH256 and BLAKE2b hashes from file.
    Actual calculation is performed only for input hashes
    which one is equal to None or empty bytes.
    `en_blake2b` flag used to force BLAKE2b calculation disabled."""

    use_sha256 = True if sha256_in in (b"", None) else False
    use_blake2b = (True if blake2b_in in (b"", None) else False) and en_blake2b
    if not use_sha256 and not use_blake2b:
        return (sha256_in, blake2b_in)  # type: ignore
    sha256_h = sha256()
    blake2b_h = blake2b()
    with open(fname, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            sha256_h.update(byte_block) if use_sha256 else None
            blake2b_h.update(byte_block) if use_blake2b else None
    return (  # type: ignore
        sha256_in if use_sha256 else sha256_h.digest(),
        blake2b_in if use_blake2b else blake2b_h.digest(),
    )


def hashes_from_file(fname: StringOrPath) -> tuple[bytes, bytes, bytes]:
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


def checksums_from_file(fname: StringOrPath) -> tuple[str, str, str]:
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


def unxz(fname: StringOrPath, mode_binary: bool = False) -> Union[bytes, str]:
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
    logger: LoggerOptional = None,
    timeout: Optional[float] = None,
) -> tuple[str, str, str, int]:
    """Run command from args. Raises exception if subprocess returns non zero code."""

    if logger is None:
        logger = logging.getLogger(__name__)
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


def dump_to_json(object: Any, file: StringOrPath) -> None:
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


class SupressStdoutStderr:
    """Context manager that supress all stdout and stderr from any function wraped in."""

    def __init__(self):
        self.null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
        self.save_fds = [os.dup(1), os.dup(2)]

    def __enter__(self):
        os.dup2(self.null_fds[0], 1)
        os.dup2(self.null_fds[1], 2)

    def __exit__(self, *_):
        os.dup2(self.save_fds[0], 1)
        os.dup2(self.save_fds[1], 2)
        for fd in self.null_fds + self.save_fds:
            os.close(fd)
