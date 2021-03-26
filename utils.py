import datetime
import logging
import re
import threading
from functools import wraps
from logging import handlers
from time import time
import argparse

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
    """COnverst file class value from RPM header to CH Enum"""
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


def sha256_from_file(fname, capitalized=False):
    """Calculates SHA256 hash from file

    Args:
        fname (path-like object or string): path to file
        capitalized (bool, optional): capitalize SHA256 hash string. Defaults to False.

    Returns:
        string: file's SHA256 hash
    """
    with open(fname, 'rb') as f:
        data = f.read()
    if capitalized:
        return sha256(data).hexdigest().upper()
    else:
        return sha256(data).hexdigest()


def md5_from_file(fname, capitalized=False):
    """Calculates MD5 hash from file

    Args:
        fname (path-like object or string): path to file
        capitalized (bool, optional): capitalize MD5 hash string. Defaults to False.

    Returns:
        string: file's MD5 hash
    """
    with open(fname, 'rb') as f:
        data = f.read()
    if capitalized:
        return md5(data).hexdigest().upper()
    else:
        return md5(data).hexdigest()


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
