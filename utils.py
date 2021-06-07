import datetime
import logging
import re
import threading
from functools import wraps
from logging import handlers
from time import time
from dateutil import tz
import json
import argparse
from pathlib import Path

import mmh3
from hashlib import sha256, md5


def mmhash(val):
    a, b = mmh3.hash64(val, signed=False)
    return a ^ b


def valid_date(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)


def get_logger(name, tag=None, date=None):
    """Create and configure logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if date is None:
        date = datetime.date.today()
    file_handler = handlers.RotatingFileHandler(
        filename='{0}-{1}-{2}.log'.format(name, tag, date.strftime('%Y-%m-%d')),
        maxBytes=2 ** 26,
        backupCount=10
    )
    fmt = logging.Formatter(
        '%(asctime)s\t%(levelname)s\t%(threadName)s\t%(funcName)s\t%(lineno)d\t%(message)s')
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter('%(asctime)s\t%(message)s'))
    stream_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


class Display:
    MSG = 'Processed {0} packages in {1:.3f} sec. {2:.3f} sec. per package on average.'

    """Show information about progress."""

    def __init__(self, log, timer_init_delta=0, step=1000):
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
        t = time() - self.timer
        self.log.info(self.MSG.format(self.step, t, t / self.step))
        self.log.info('Total: {0}'.format(self.counter))

    def _update(self):
        self.counter += 1
        t = time()
        self.timesum_short += t - self.timer_short
        self.timer_short = time()
        if self.counter % self.step == 0:
            self._showmsg()
            t = time()
            self.timesum += t - self.timer
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
        self.log.info(self.MSG.format(self.counter, self.timesum,
                                      self.timesum / (self.counter if self.counter else 1)))


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
                    log.debug('F:{0} T:{1:.5f}'.format(f.__name__, te - ts))
                return result

            return wrap

        return timer


def cvt(b, t=str):
    """Convert byte string or list of byte strings to strings
    or list strings.
    """
    if isinstance(b, bytes) and t is str:
        return b.decode('latin-1')
    if isinstance(b, list):
        return [cvt(i) for i in b]
    if b is None:
        if t is bytes: return ''
        if t is str: return ''
        if t is int: return 0
    return b


def changelog_date_format(ts):
    """Convert timestamp to the changelog date format."""
    dt = datetime.date.fromtimestamp(ts)
    return dt.strftime("%a %b %d %Y")


def cvt_ts(ts):
    """Convert timestamp or list of timestamps to datetime object or list 
    of datetime objects.
    """
    if isinstance(ts, int):
        return datetime.datetime.fromtimestamp(ts)
    if isinstance(ts, list):
        return [cvt_ts(i) for i in ts]
    return ts


def changelog_to_text(dates, names, texts):
    """Compile changelog records to plain text."""
    if not len(dates) == len(names) == len(texts):
        raise ValueError
    text = ""
    for d, n, t in zip(dates, names, texts):
        text += "* {0} {1}\n{2}\n\n".format(changelog_date_format(d), cvt(n),
                                            cvt(t))
    return text


def changelog_to_dict(dates, names, texts):
    """Compile changelog records to dict of elements"""
    if not len(dates) == len(names) == len(texts):
        raise ValueError
    chlog = {}
    for d, n, t in zip(dates, names, texts):
        tmp = cvt(n)
        # tmp = tmp.split('>')
        if len(tmp.split('>')) == 2:
            name = tmp.split('>')[0] + '>'
            evr = tmp.split('>')[1].strip()
        else:
            # TODO: try to parse changelog name record to get release info if available
            name = tmp
            evr = ''
        chlog[mmhash(cvt(t))] = (int(d), name, evr, cvt(t))
    return chlog


def convert_file_class(fc: str):
    """Converts file class value from RPM header to CH Enum"""
    lut = {
        'directory': 'directory',
        'symbolic link to': 'symlink',
        'socket': 'socket',
        'character special': 'char',
        'block special': 'block',
        'fifo (named pipe)': 'fifo',
        'file': 'file',
    }
    if fc == '':
        return lut['file']
    else:
        for k, v in lut.items():
            if fc.startswith(k):
                return v
    return ''


packager_pattern = re.compile('([\w. ]+?) (\(.+?\) )?<(.+?)>')


def packager_parse(packager):
    """Parse packager.

    return tuple of name and email or None
    """
    m = packager_pattern.search(packager)
    if m is not None:
        return m.group(1), m.group(3)


class LockedIterator:
    def __init__(self, it):
        self.it = it
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            return next(self.it)


def strip_end(text, suffix):
    if text.endswith(suffix):
        return text[:-len(suffix)]
    return text


def symbolic(text):
    if text.startswith('symbolic'):
        return 'symbolic'
    return text


class Cache:
    def __init__(self, callback):
        self.__data = {}
        self.callback = callback

    def get(self, key):
        value = self.__data.get(key, None)
        if value is None:
            value = self.callback(key)
            self.__data[key] = value
        return value

    def load(self, it):
        for k, v in it:
            self.__data[k] = v


def chunks(data, size):
    it = iter(data)
    while True:
        acc = []
        try:
            for _ in range(size):
                acc.append(next(it))
        except StopIteration:
            break
        finally:
            yield acc


def sha256_from_file(fname, as_bytes=False, capitalized=False):
    """Calculates SHA256 hash from file

    Args:
        fname (path-like object or string): path to file
        as_bytes (bool, otional): return hash as raw bytes. Defaults to False
        capitalized (bool, optional): capitalize SHA256 hash string. Defaults to False.

    Returns:
        string or bytes: file's SHA256 hash
    """
    sha256_hash = sha256()
    with open(fname, 'rb') as f:
        for byte_block in iter(lambda: f.read(8192),b""):
            sha256_hash.update(byte_block)
    if as_bytes:
        return sha256_hash.digest()
    if capitalized:
        return sha256_hash.hexdigest().upper()
    else:
        return sha256_hash.hexdigest()


def md5_from_file(fname, as_bytes=False, capitalized=False):
    """Calculates MD5 hash from file

    Args:
        fname (path-like object or string): path to file
        as_bytes (bool, otional): return hash as raw bytes. Defaults to False
        capitalized (bool, optional): capitalize MD5 hash string. Defaults to False.

    Returns:
        string or bytes: file's MD5 hash
    """
    md5_hash = md5()
    with open(fname, 'rb') as f:
        for byte_block in iter(lambda: f.read(8192),b""):
            md5_hash.update(byte_block)
    if as_bytes:
        return md5_hash.digest()
    if capitalized:
        return md5_hash.hexdigest().upper()
    else:
        return md5_hash.hexdigest()


def join_dicts_with_as_string(d1, d2, key):
    """Join dictionary with dictionary, list, tuple or any object
    that can be represented as string.
    Stringify all elements of joined object if it is not dictionary.
    Do not preserve value in original dictionary if given 'key' exists.
    If joined object is not dictionary and key is None returns original dictionary.

    Args:
        d1 (dict): dictionary to join with
        d2 (any): dictionary or any object that has string representation
        key (any, optional): key for joined object

    Returns:
        dict: joined dictionary
    """
    res = d1
    if not isinstance(d1, dict):
        return d1
    if isinstance(d2, dict):
        res.update(d2)
        # return res
    elif isinstance(d2, list) or isinstance(d2, tuple):
        if key is None:
            return d1
        res.update({key: ', '.join([str(v) for v in d2])})
    else:
        if key is None:
            return d1
        res.update({key: str(d2)})
    return res


class FunctionalNotImplemented(Exception):
    """Exception raised for not implemented functional

    Attributes:
        function - not implemented function description
    """

    def __init__(self, function, message="Functional not implemented"):
        self.function = function
        self.message = message


def cvt_ts_to_datetime(ts, use_local_tz=False):
    """Converts timestamp to datetime object as UTC or local time

    Args:
        ts (int | float): Timestamp
        use_local_tz (bool, optional): Use local time zone. Defaults to False.

    Returns:
        datetime: Converted timestamp as datetime object
    """
    utc = datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=tz.tzutc())
    if use_local_tz:
        return utc.astimezone(tz.tzlocal())
    else:
        return utc


def cvt_datetime_local_to_utc(dt):
    dt = dt.replace(tzinfo=tz.tzlocal())
    return dt.astimezone(tz.tzutc())


def val_from_json_str(json_str, val_key):
    """Returns value from stringified JSON

    Args:
        json_str (str): stringified JSON
        val_key (str): key to lookup value in JSON

    Returns:
        any: value found in JSON or None
    """
    if json_str is None or json_str == '':
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


class GeneratorWrapper:
    """Wraps generator function and allow to test it's emptyness at any time 
    """
    def __init__(self, iter):
        self.source = iter
        self.stored = False

    def __iter__(self):
        return self

    def __bool__(self):
        if self.stored:
            return True
        try:
            self.value = next(self.source)
            self.stored = True
        except StopIteration:
            return False
        return True

    def __next__(self):
        if self.stored:
            self.stored = False
            return self.value
        return next(self.source)


def log_parser(logger, log_file, log_type, log_start_time):
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
    events_pattern = re.compile('^\d{4}-[A-Z][a-z]{2}-\d{2}\s\d{2}:\d{2}:\d{2}')
    # matches with '<13>Sep 13 17:53:14 '
    srpm_pattern = re.compile('^<\d+>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}')
    # matches with '[00:03:15] '
    build_pattern = re.compile('^\[\d{2}:\d{2}:\d{2}\]')

    if not Path(log_file).is_file():
        logger.error(f"File '{log_file}' not found")
        return ()
    else:
        with Path(log_file).open('r', encoding='utf-8', errors='backslashreplace') as f:
            first_line = True
            line_cnt = 0
            for line in f:
                if len(line) > 0:
                    if log_type == 'events':
                        line_cnt += 1
                        if first_line:
                            dt = events_pattern.findall(line)
                            if not dt:
                                logger.error(f"File '{log_file}' first line doesn't contain valid datetime."
                                            f" Log file parsing aborted.")
                                return tuple()
                            dt = dt[0]
                            msg = events_pattern.split(line)[-1].split(' :: ')[-1].strip()
                            last_dt = dt
                            first_line = False
                            yield (
                                line_cnt,
                                datetime.datetime.strptime(dt, '%Y-%b-%d %H:%M:%S'),
                                msg,
                            )
                        else:
                            dt = events_pattern.findall(line)
                            msg = events_pattern.split(line)[-1].split(' :: ')[-1].strip()
                            if dt:
                                dt = dt[0]
                                last_dt = dt
                                yield (
                                    line_cnt,
                                    datetime.datetime.strptime(dt, '%Y-%b-%d %H:%M:%S'),
                                    msg,
                                )
                            else:
                                yield (
                                    line_cnt,
                                    datetime.datetime.strptime(last_dt, '%Y-%b-%d %H:%M:%S'),
                                    msg,
                                )
                    elif log_type == 'srpm':
                        if not isinstance(log_start_time, datetime.datetime):
                            logger.error(f"Valid 'log_start_time' value is required to parse 'srpm.log'" 
                                        f" type file {log_file}. Log file parsing aborted.")
                            return ()
                        line_cnt += 1
                        dt = srpm_pattern.findall(line)
                        msg = srpm_pattern.split(line)[-1].strip()
                        if dt:
                            dt = dt[0]
                            last_dt = dt
                            first_line = False
                            # FIXME: workaround for 'Feb 29' (https://bugs.python.org/issue26460)
                            ts_str = f"{str(log_start_time.year)} " + ' '.join([_ for _ in dt[4:].split(' ') if len(_) > 0])
                            ts = datetime.datetime.strptime(ts_str, '%Y %b %d %H:%M:%S')
                            yield (line_cnt, ts, msg,)
                        else:
                            if first_line:
                                logger.debug(f"File '{log_file}' first line doesn't contain valid datetime."
                                            f" Using 'log_start_time' as timestamp.")
                                ts = log_start_time
                            else:
                                ts_str = f"{str(log_start_time.year)} " + ' '.join([_ for _ in last_dt[4:].split(' ') if len(_) > 0])
                                ts = datetime.datetime.strptime(ts_str, '%Y %b %d %H:%M:%S')
                            yield (line_cnt, ts, msg,)
                    elif log_type == 'build':
                        line_cnt += 1
                        ts = build_pattern.findall(line)
                        msg = build_pattern.split(line)[-1].strip()
                        if ts:
                            ts = ts[0][1:-1].split(':')
                            ts = log_start_time \
                                + datetime.timedelta(
                                    hours=int(ts[0]),
                                    minutes=int(ts[1]),
                                    seconds=int(ts[2])
                                    )
                        else:
                            ts = log_start_time
                        yield (line_cnt, ts, msg,)
                    else:
                        logger.error(f"Unknown log format specifier '{log_type}'.  Log file parsing aborted.")
                        return tuple()


def parse_hash_diff(hash_file):
    """Parse hash diff file.
    Returns added and deleted hashes as dictionaries

    Args:
        hash_file (str): hash diff file name

    Returns:
        (dict, dict): added hashses, deleted hashes
    """
    hash_pattern = re.compile('^[+-]+[0-9a-f]{64}\s+')
    h_added = {}
    h_deleted = {}
    try:
        contents = Path(hash_file).read_text()
        contents = (_ for _ in contents.split('\n') if len(_) > 0)
    except FileNotFoundError:
        return {}, {}
    for line in contents:
        h = hash_pattern.findall(line)
        if h:
            sign = h[0][0]
            sha256 = h[0][1:].strip()
            pkg_name = hash_pattern.split(line)[-1].strip()
            if sign == '+':
                h_added[pkg_name] = bytes.fromhex(sha256)
            else:
                h_deleted[pkg_name] = bytes.fromhex(sha256)
    return h_added, h_deleted

def parse_pkglist_diff(diff_file, is_src_list):
    """Parse package list diff file.
    Returns added and deleted packages lists

    Args:
        diff_file (str): package list diff file
        is_src_list (bool): parse file as source packages list or binary packages list

    Returns:
        (list(tuple), list(tuple)): added packages, deleted packages
    """
    diff_pattern = re.compile('^[+-]+[a-zA-Z0-9]+\S+')
    p_added = []
    p_deleted = []
    try:
        contents = Path(diff_file).read_text()
        contents = (_ for _ in contents.split('\n') if len(_) > 0)
    except FileNotFoundError:
        return [], []
    for line in contents:
        p = diff_pattern.findall(line)
        if p:
            sign = p[0][0]
            if is_src_list:
                pkg_name = p[0][1:].strip()
                pkg_evr, pkg_file = [_.strip() for _ in diff_pattern.split(line)[-1].split('\t') if len(_) > 0]
                pkg_src = pkg_file
                pkg_arch = 'src'
            else:
                pkg_name = p[0][1:].strip()
                pkg_evr, pkg_arch, pkg_file, pkg_src = [_.strip() for _ in diff_pattern.split(line)[-1].split('\t') if len(_) > 0]
            if sign == '+':
                p_added.append((pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch))
            else:
                p_deleted.append((pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch))
    return p_added, p_deleted
