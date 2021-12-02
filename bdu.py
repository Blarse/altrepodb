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
from utils import get_logger


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
        dt = datetime.datetime.strptime(self.identify_date, '%d.%m.%Y').date()
        record = dict(
            bdu_identifier=self.identifier,
            bdu_name=self.name,
            bdu_description=self.description,
            bdu_identify_date=dt,
            bdu_severity=self.severity,
            bdu_solution=self.solution,
            bdu_vul_status=self.vul_status,
            bdu_exploit_status=self.exploit_status,
            bdu_fix_status=self.fix_status,
            bdu_sources=self.sources,
            bdu_other=self.other
        )
        vs = self.vulnerable_software
        env = self.environment
        cvss = self.cvss
        identifiers = self.identifiers
        record['bdu_vulnerable_software.vendor'] = [i['vendor'] for i in vs]
        record['bdu_vulnerable_software.type'] = [i['types'] for i in vs]
        record['bdu_vulnerable_software.name'] = [i['name'] for i in vs]
        record['bdu_vulnerable_software.version'] = [i['version'] for i in vs]
        record['bdu_environment.vendor'] = [i['vendor'] for i in env]
        record['bdu_environment.version'] = [i['version'] for i in env]
        record['bdu_environment.name'] = [i['name'] for i in env]
        record['bdu_environment.platform'] = [i['platform'] for i in env]
        record['bdu_cwe.identifier'] = self.cwe
        record['bdu_cvss.vector'] = [i.text for i in cvss]
        record['bdu_cvss.score'] = [float(i.attrib.get('score')) for i in cvss]
        record['bdu_identifiers.identifier'] = [i.text for i in identifiers]
        record['bdu_identifiers.type'] = [i.get('type', '') for i in identifiers]
        record['bdu_identifiers.link'] = [i.get('link', '') for i in identifiers]
        return record


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
    sql = """INSERT INTO FstecBduList (bdu_identifier, bdu_name,
                          bdu_description, bdu_identify_date, bdu_severity,
                          bdu_solution,
                          bdu_vul_status, bdu_exploit_status, bdu_fix_status,
                          bdu_sources,
                          bdu_other, bdu_vulnerable_software.vendor,
                          bdu_vulnerable_software.type,
                          bdu_vulnerable_software.name,
                          bdu_vulnerable_software.version,
                          bdu_environment.vendor,
                          bdu_environment.version, bdu_environment.name,
                          bdu_environment.platform, bdu_cwe.identifier,
                          bdu_cvss.vector,
                          bdu_cvss.score, bdu_identifiers.identifier,
                          bdu_identifiers.type, bdu_identifiers.link)
VALUES"""


    data = []
    log.info('parsing xml')
    for vul in xml.iterchildren():
        data.append(Vul(vul).make_insert())
    log.info('save data from xml to database')
    conn.execute(sql, data)
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
