import clickhouse_driver as chd
import sys
import datetime
import zipfile
import logging
import argparse
import configparser
import urllib.request as req
from lxml import etree
from io import BytesIO
from itertools import product
from utils import get_logger, chunks


NAME = 'bdu'

log = logging.getLogger(NAME)


class Vul:

    FIELDS = [
        'identifier',
        'name',
        'description',
        'identify_date',
        'severity',
        'solution',
        'vul_status',
        'exploit_status',
        'fix_status',
        'sources',
        'other'
    ]

    def __init__(self, element):
        self._root = element
        if not isinstance(self._root, etree._Element):
            raise ValueError

    def _unwrap(self, element_name):
        result = []
        try:
            elist = self._root.xpath(element_name)[0]
        except IndexError:
            return result
        for i in elist:
            result.append(dict([(j.tag, j.text) for j in i.getchildren()]))
        return result


    def __getattr__(self, name):
        if name in self.FIELDS:
            try:
                return self._root.xpath('{0}/text()'.format(name))[0]
            except IndexError:
                return ''
        else:
            raise AttributeError

    @property
    def vulnerable_software(self):
        result = []
        try:
            elist = self._root.xpath('vulnerable_software')[0]
        except IndexError:
            return result
        for i in elist:
            field = []
            for j in i.iterchildren():
                if j.tag == 'types':
                    field.append((j.tag, j.xpath('type/text()')))
                else:
                    field.append((j.tag, j.text))
            result.append(dict(field))
        return result

    @property
    def environment(self):
        return self._unwrap('environment')

    @property
    def cwe(self):
        return self._root.xpath('cwe/identifier/text()')

    @property
    def cvss(self):
        return self._root.xpath('cvss/vector')

    @property
    def identifiers(self):
        return self._root.xpath('identifiers/identifier')

    def make_insert(self):
        result = []
        general = dict(
            bdu_identifier=self.identifier,
            bdu_name=self.name,
            bdu_description=self.description,
            bdu_identify_date=datetime.datetime.strptime(self.identify_date, '%d.%m.%Y'),
            bdu_severity=self.severity,
            bdu_solution=self.solution,
            bdu_vul_status=self.vul_status,
            bdu_exploit_status=self.exploit_status,
            bdu_fix_status=self.fix_status,
            bdu_sources=self.sources,
            bdu_other=self.other
        )
        for vs, env, cwe, cvss, idef in product(self.vulnerable_software, self.environment, self.cwe, self.cvss, self.identifiers):
            for vs_type in vs['types']:
                record = general.copy()
                record.update(
                    bdu_vulnerable_software_vendor=vs['vendor'],
                    bdu_vulnerable_software_type=vs_type,
                    bdu_vulnerable_software_name=vs['name'],
                    bdu_vulnerable_software_version=vs['version'],
                    bdu_environment_vendor=env['vendor'],
                    bdu_environment_version=env['version'],
                    bdu_environment_name=env['name'],
                    bdu_environment_platform=env['platform'],
                    bdu_cwe=cwe,
                    bdu_cvss=cvss.text,
                    bdu_cvss_score=float(cvss.attrib.get('score')),
                    bdu_identifiers=idef.text,
                    bdu_identifiers_type=idef.attrib.get('type'),
                    bdu_identifiers_link=idef.attrib.get('link', 'test')
                )
                result.append(record)
        return result


def read_xml(xmldata):
    log.info('read xml')
    return etree.XML(xmldata)


def download(url):
    log.info('download zip archive from {0}'.format(url))
    resp = req.urlopen(url)
    if resp.status == 200:
        log.info('read zip archive')
        data = resp.read()
        zipdata = BytesIO(data)
        zipdata.seek(0)
        return zipdata


def unzip(zipdata):
    log.info('unzip archive')
    with zipfile.ZipFile(zipdata) as xmlzip:
        with xmlzip.open('export/export.xml') as f:
            return f.read()


def cleanup(conn):
    log.info('cleanup FstecBduList table')
    conn.execute('TRUNCATE TABLE FstecBduList')


def write2db(conn, xml):
    sql = (
        'INSERT INTO FstecBduList (bdu_identifier, bdu_name, '
        'bdu_description, bdu_identify_date, bdu_severity, bdu_solution, '
        'bdu_vul_status, bdu_exploit_status, bdu_fix_status, bdu_sources, '
        'bdu_other, bdu_vulnerable_software_vendor, '
        'bdu_vulnerable_software_type, bdu_vulnerable_software_name, '
        'bdu_vulnerable_software_version, bdu_environment_vendor, '
        'bdu_environment_version, bdu_environment_name, '
        'bdu_environment_platform, bdu_cwe, bdu_cvss, bdu_cvss_score, '
        'bdu_identifiers, bdu_identifiers_type, bdu_identifiers_link) VALUES'
    )

    data = []
    log.info('parsing xml')
    for vul in xml.iterchildren():
        data.extend(Vul(vul).make_insert())
    log.info('save data from xml to database')
    for chunk in chunks(data, 100000):
        conn.execute(sql, chunk)
    log.info('{0} records saved to database'.format(len(data)))


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database password')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    args = parser.parse_args()
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        if cfg.has_section('DATABASE'):
            section_db = cfg['DATABASE']
            args.dbname = args.dbname or section_db.get('dbname', 'default')
            args.host = args.host or section_db.get('host', 'localhost')
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', 'default')
            args.password = args.password or section_db.get('password', '')
    else:
        args.dbname = args.dbname or 'default'
        args.host = args.host or 'localhost'
        args.port = args.port or None
        args.user = args.user or 'default'
        args.password = args.password or ''
    return args


def load(conn):
    log.info('start loading')
    zipdata = download('https://bdu.fstec.ru/documents/files/vulxml.zip')
    xmldata = unzip(zipdata)
    xml = read_xml(xmldata)
    cleanup(conn)
    write2db(conn, xml)
    log.info('stop loading')


def main():
    args = get_args()
    logger = get_logger(NAME)
    logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        load(conn)
    except Exception as error:
        logger.error(error, exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == '__main__':
    main()
