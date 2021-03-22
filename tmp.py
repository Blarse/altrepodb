import urllib.request
import os
import logging
import json
import rpm
from utils import get_logger, cvt, mmhash
import extract

NAME = 'task'

os.environ['LANG'] = 'C'

log = logging.getLogger(NAME)

# parse task sha256 hashes
# url1 = 'http://git.altlinux.org/tasks/archive/done/_260/267022/plan/x86_64.hash.diff'
#
# r = urllib.request.urlopen(url1)
# if r.getcode() == 200:
#     # resp = r.read().decode('utf-8')
#     resp = r.read().decode('latin-1')
#     for line in resp.split('\n'):
#         ll = line.split('  ')
#         if len(ll) == 2 and ll[0][0:1] == '+':
#             print(f"ADD: SHA256 : {ll[0][2:]} \tPackage : {ll[1]}")
#         elif len(ll) == 2 and ll[0][0:1] == '-':
#             print(f"REMOVE: SHA256 : {ll[0][2:]} \tPackage : {ll[1]}")
# ts = rpm.TransactionSet()
# rpmfile = '/home/dshein/src/packages/dunst-1.5.0-alt1.x86_64.rpm'
# hdr = ts.hdrFromFdno(rpmfile)
#
# print(cvt(hdr[rpm.RPMDBI_SHA1HEADER]), hex(int.from_bytes(hdr[rpm.RPMDBI_SIGMD5], byteorder='little')))


class Girar:
    def __init__(self, url):
        self.url = url
        self.ts = rpm.TransactionSet()

    def _get_content(self, url, status=False):
        try:
            r = urllib.request.urlopen(url)
        except urllib.error.URLError as e:
            log.debug('{0} - {1}'.format(e, url))
            if status:
                return False
            return None
        except Exception as e:
            log.error('{0} - {1}'.format(e, url))
            return None
        if r.getcode() == 200:
            if status:
                return True
            return cvt(r.read())

    def get(self, method, status=False):
        p = os.path.join(self.url, method)
        r = self._get_content(p, status)
        return r

    def check(self):
        return self._get_content(self.url, status=True)

    def get_header(self, path):
        return extract.get_header(self.ts, os.path.join(self.url, path))


class Task:
    def __init__(self, girar):
        self.girar = girar
        # self.cache = extract.init_cache(self.conn)
        self._prepare_fields()

    def _prepare_fields(self):
        self.info_json = json.loads(cvt(self.girar.get('info.json')))

        self.fields = {
            'task_id': int(self.girar.get('task/id').strip()),
            'task_message': (self.girar.get('task/message') or '').strip(),
            'task_changed': '',
            'task_prev': int('0'),
            'task_try': int(self.girar.get('task/try').strip()),
            'task_iteration': int(self.girar.get('task/iter').strip()),
            'task_state': self.girar.get('task/state').strip(),
            'task_testonly': self.girar.get('task/test-only', status=True),
            'task_repo': self.girar.get('task/repo').strip(),
            'task_owner': self.girar.get('task/owner').strip(),
            'task_shared': '',
            'task_version': self.girar.get('task/version').strip(),
            'task_run': self.girar.get('task/run').strip()
        }

    def save(self):
        print('JSON:')
        print(self.info_json)
        print('Fields')
        print(self.fields)


class Args(object):
    pass


def main():
    args = Args
    # args.url = 'http://git.altlinux.org/tasks/archive/done/_260/267037'
    args.url = 'http://git.altlinux.org/tasks/archive/done/_259/265234'

    girar = Girar(args.url)
    if girar.check():
        task = Task(girar)
        task.save()
    else:
        raise ValueError('task not found: {0}'.format(args.url))


if __name__ == '__main__':
    main()
