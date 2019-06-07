import re
import datetime
import logging
import threading
from logging import handlers
from functools import wraps
from time import time


def get_logger(name, tag='none'):
    """Create and configure logger."""
    logger = logging.getLogger(name)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh = handlers.RotatingFileHandler(
        filename='{0}_{1}.log'.format(name, tag),
        maxBytes=2**26,
        backupCount=10
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)
    return logger


class Display:
    MSG = 'Processed {0} packages in {1:.2f} sec. {2:.3f} sec. per package on average.'

    """Show information about progress."""
    def __init__(self, step=1000):
        self.lock = threading.Lock()
        self.counter = 0
        self.timer = None
        self.step = step
        self.timesum = 0

    def _showmsg(self):
        t = time() - self.timer
        print(self.MSG.format(self.step, t, t / self.step))

    def _update(self):
        self.counter += 1
        if self.counter % self.step == 0:
            self._showmsg()
            t = time()
            self.timesum += t - self.timer
            self.timer = time()

    def inc(self):
        with self.lock:
            if self.timer is None:
                self.timer = time()
            self._update()

    def conclusion(self):
        print('=' * 80)
        print(self.MSG.format(self.counter, self.timesum, self.timesum / self.counter))


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
                    log.info('F:{0} T:{1:.5f}'.format(f.__name__, te-ts))
                return result
            return wrap
        return timer


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


def get_conn_str(args):
    r = []
    if args.dbname is not None:
        r.append("dbname={0}".format(args.dbname))
    if args.user is not None:
        r.append("user={0}".format(args.user))
    if args.password is not None:
        r.append("password={0}".format(args.password))
    if args.host is not None:
        r.append("host={0}".format(args.host))
    if args.port is not None:
        r.append("port={0}".format(args.port))
    return ' '.join(r)


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
    if text.startswith('symbolic')
        return 'symbolic'
    return text
