import os
import re
import json
import lzma
import mmh3
import logging
import argparse
import datetime
import threading
from time import time
from dateutil import tz
from pathlib import Path
from functools import wraps
from logging import handlers
from dataclasses import dataclass
from hashlib import sha256, md5, blake2b
from clickhouse_driver import Client
from typing import Any, Iterable, Union, Hashable, Generator

from altrpm import rpm

# custom types
_FileName = Union[str, os.PathLike]


def mmhash(val: Any) -> int:
    """Calculate MurmurHash3 64-bit value."""

    a, b = mmh3.hash64(val, signed=False)
    return a ^ b


def snowflake_id(hdr: dict, epoch: int = 1_000_000_000) -> int:
    """Genarates showflake-like ID using data from RPM package header object.
    Returns 64 bit wide unsigned integer:
        - most significant 32 bits package build time delta from epoch
        - less significant bits are mutmurHash from package sign header (SHA1 + MD5 + GPG)

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
            gpg_ += k
        gpg = gpg_

    data = sha1 + md5 + gpg
    sf_hash = mmh3.hash(data, signed=False)
    sf_ts = buildtime - epoch
    sf_id = (sf_ts << 32) | (sf_hash & 0xFFFFFFFF)

    return sf_id


def valid_date(s: str) -> datetime.datetime:
    """Convert string to datetime object or rise an error."""

    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)


def check_package_in_cache(cache: Iterable, pkghash: Any) -> Union[Any, None]:
    """Check whether the hash is in the cache."""

    if pkghash in cache:
        return pkghash
    return None


def get_client(args: Any) -> Client:
    """Get Clickhouse client instance."""

    client = Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password,
    )
    client.connection.connect()

    return client


def get_logger(
    name: str, tag: str = "", date: Union[datetime.date, None] = None
) -> logging.Logger:
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
        self, log: logging.Logger, timer_init_delta: float = 0, step: int = 1000
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


def log_parser(
    logger: logging.Logger,
    log_file: _FileName,
    log_type: str,
    log_start_time: datetime.datetime,
) -> Generator:
    """Task logs parser generator

    Args:
        logger (logger): Logger instance object
        log_file (str): log file name
        log_type (str): log type ('events'|'build'|'srpm')
        log_start_time (datetime): log start time for logs with partial or none timestamps included

    Returns:
        generator(tuple(tuple(int, datetime, str),)): return parsed log as generator of tuples of line number, timestamp and message
    """
    # matches with '2020-May-15 10:30:00 '
    events_pattern = re.compile("^\d{4}-[A-Z][a-z]{2}-\d{2}\s\d{2}:\d{2}:\d{2}")  # type: ignore
    # matches with '<13>Sep 13 17:53:14 '
    srpm_pattern = re.compile("^<\d+>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}")  # type: ignore
    # matches with '[00:03:15] '
    build_pattern = re.compile("^\[\d{2}:\d{2}:\d{2}\]")  # type: ignore

    if not Path(log_file).is_file():
        logger.error(f"File '{log_file}' not found")
        return tuple()
    else:
        with Path(log_file).open("r", encoding="utf-8", errors="backslashreplace") as f:
            first_line = True
            line_cnt = 0
            for line in f:
                if len(line) > 0:
                    if log_type == "events":
                        line_cnt += 1
                        if first_line:
                            dt = events_pattern.findall(line)
                            if not dt:
                                logger.error(
                                    f"File '{log_file}' first line doesn't contain valid datetime."
                                    f" Log file parsing aborted."
                                )
                                return tuple()
                            dt = dt[0]
                            msg = (
                                events_pattern.split(line)[-1].split(" :: ")[-1].strip()
                            )
                            last_dt = dt
                            first_line = False
                            yield (
                                line_cnt,
                                datetime.datetime.strptime(dt, "%Y-%b-%d %H:%M:%S"),
                                msg,
                            )
                        else:
                            dt = events_pattern.findall(line)
                            msg = (
                                events_pattern.split(line)[-1].split(" :: ")[-1].strip()
                            )
                            if dt:
                                dt = dt[0]
                                last_dt = dt
                                yield (
                                    line_cnt,
                                    datetime.datetime.strptime(dt, "%Y-%b-%d %H:%M:%S"),
                                    msg,
                                )
                            else:
                                yield (
                                    line_cnt,
                                    datetime.datetime.strptime(
                                        last_dt, "%Y-%b-%d %H:%M:%S"  # type: ignore
                                    ),
                                    msg,
                                )
                    elif log_type == "srpm":
                        if not isinstance(log_start_time, datetime.datetime):
                            logger.error(
                                f"Valid 'log_start_time' value is required to parse 'srpm.log'"
                                f" type file {log_file}. Log file parsing aborted."
                            )
                            return ()
                        line_cnt += 1
                        dt = srpm_pattern.findall(line)
                        msg = srpm_pattern.split(line)[-1].strip()
                        if dt:
                            dt = dt[0]
                            last_dt = dt
                            first_line = False
                            # FIXME: workaround for 'Feb 29' (https://bugs.python.org/issue26460)
                            ts_str = f"{str(log_start_time.year)} " + " ".join(
                                [x for x in dt[4:].split(" ") if len(x) > 0]
                            )
                            ts = datetime.datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                            yield (
                                line_cnt,
                                ts,
                                msg,
                            )
                        else:
                            if first_line:
                                logger.debug(
                                    f"File '{log_file}' first line doesn't contain valid datetime."
                                    f" Using 'log_start_time' as timestamp."
                                )
                                ts = log_start_time
                            else:
                                ts_str = f"{str(log_start_time.year)} " + " ".join(
                                    [x for x in last_dt[4:].split(" ") if len(x) > 0]  # type: ignore
                                )
                                ts = datetime.datetime.strptime(
                                    ts_str, "%Y %b %d %H:%M:%S"
                                )
                            yield (
                                line_cnt,
                                ts,
                                msg,
                            )
                    elif log_type == "build":
                        line_cnt += 1
                        ts = build_pattern.findall(line)
                        msg = build_pattern.split(line)[-1].strip()
                        if ts:
                            ts = ts[0][1:-1].split(":")
                            ts = log_start_time + datetime.timedelta(
                                hours=int(ts[0]), minutes=int(ts[1]), seconds=int(ts[2])
                            )
                        else:
                            ts = log_start_time
                        yield (
                            line_cnt,
                            ts,
                            msg,
                        )
                    else:
                        logger.error(
                            f"Unknown log format specifier '{log_type}'.  Log file parsing aborted."
                        )
                        return tuple()


def parse_hash_diff(hash_file: _FileName) -> tuple[dict, dict]:
    """Parse hash diff file. Returns added and deleted hashes as dictionaries."""

    hash_pattern = re.compile("^[+-]+[0-9a-f]{64}\s+")  # type: ignore
    h_added = {}
    h_deleted = {}
    try:
        contents = Path(hash_file).read_text()
        contents = (x for x in contents.split("\n") if len(x) > 0)
    except FileNotFoundError:
        return {}, {}
    for line in contents:
        h = hash_pattern.findall(line)
        if h:
            sign = h[0][0]
            sha256 = h[0][1:].strip()
            pkg_name = hash_pattern.split(line)[-1].strip()
            if sign == "+":
                h_added[pkg_name] = bytes.fromhex(sha256)
            else:
                h_deleted[pkg_name] = bytes.fromhex(sha256)
    return h_added, h_deleted


def parse_pkglist_diff(diff_file: _FileName, is_src_list: bool) -> tuple[list, list]:
    """Parse package list diff file. Returns tuple of added and deleted packages lists."""

    @dataclass(frozen=True)
    class PkgInfo:
        """Represents package info from task plan"""

        name: str
        evr: str
        file: str
        srpm: str
        arch: str

    diff_pattern = re.compile("^[+-]+[a-zA-Z0-9]+\S+")  # type: ignore
    p_added: list[PkgInfo] = []
    p_deleted: list[PkgInfo] = []
    try:
        contents = Path(diff_file).read_text()
        contents = (x for x in contents.split("\n") if len(x) > 0)
    except FileNotFoundError:
        return [], []
    for line in contents:
        p = diff_pattern.findall(line)
        if p:
            sign = p[0][0]
            if is_src_list:
                pkg_name = p[0][1:].strip()
                pkg_evr, pkg_file = [
                    x.strip()
                    for x in diff_pattern.split(line)[-1].split("\t")
                    if len(x) > 0
                ]
                pkg_src = pkg_file
                pkg_arch = "src"
            else:
                pkg_name = p[0][1:].strip()
                pkg_evr, pkg_arch, pkg_file, pkg_src = [
                    x.strip()
                    for x in diff_pattern.split(line)[-1].split("\t")
                    if len(x) > 0
                ]
            if sign == "+":
                p_added.append(PkgInfo(pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch))
            else:
                p_deleted.append(
                    PkgInfo(pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch)
                )
    return p_added, p_deleted
