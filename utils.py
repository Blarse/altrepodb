import re
import datetime
import logging
from logging import handlers
from functools import wraps
from time import time


def get_logger(name):
    """Create and configure logger."""
    logger = logging.getLogger(name)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = handlers.RotatingFileHandler(
        filename='{0}.log'.format(name),
        maxBytes=2**26,
        backupCount=10
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.setLevel(logging.DEBUG)
    return logger


def timing(f):
    """Measuring execution time."""
    log = logging.getLogger('extract')
    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        # log.debug('F:{0} args:[{1},{2}] took: {3:.5f}s'.format(f.__name__, args, kw, te-ts))
        log.debug('F:{0} took: {1:.5f}s'.format(f.__name__, te-ts))
        return result
    return wrap


def cvt(b):
    """Convert byte string or list of byte strings to strings
    or list strings.
    """
    if isinstance(b, bytes):
        return b.decode('latin-1')
    if isinstance(b, list):
        return [cvt(i) for i in b]
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
        text += "* {0} {1}\n{2}\n\n".format(changelog_date_format(d), cvt(n), cvt(t))
    return text


packager_pattern = re.compile('([\w. ]+?) (\(.+?\) )?<(.+?)>')

def packager_parse(packager):
    """Parse packager.

    return tuple of name and email or None
    """
    m = packager_pattern.search(packager)
    if m is not None:
        return m.group(1), m.group(3)
