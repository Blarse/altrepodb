import sys
import logging
import argparse
import requests
import datetime
from requests import HTTPError
import configparser
from collections import namedtuple
from dataclasses import dataclass
from clickhouse_driver import Client
from pathlib import Path
import json

from utils import get_logger, cvt_datetime_local_to_utc
from htmllistparse import fetch_listing


NAME = "beehive"

log = logging.getLogger(NAME)

Endpoint = namedtuple("Endpoint", ["name", "type", "path", "destination"])
Target = namedtuple("Target", ["branch", "arch", "name", "type", "url", "destination"])
Package = namedtuple("Package", ["name", "version", "release"])
PackageInfo = namedtuple("PackageInfo", ["package", "modified", "size"])
FileInfo = namedtuple("FileInfo", ["name", "modified", "size"])
TargetKey = namedtuple("TargetKey", ["branch", "arch", "name"])

BEEHIVE_BASE_URL = "http://git.altlinux.org/beehive/logs"
BEEHIVE_BRANCHES = (
    "Sisyphus",
    "p10",
    "p9",
)
# BEEHIVE_BRANCHES = ("p10",)
BEEHIVE_ARCHS = ("i586", "x86_64")
BEEHIVE_ENDPOINTS = (
    Endpoint("latest_dir_mtime", "dir", "", "latest"),
    Endpoint("time_file_listing", "file", "latest/time.list", None),
    Endpoint("error_dir_listing", "dir", "latest/error", None),
    Endpoint("success_dir_listing", "dir", "latest/success", None),
    # Endpoint("latest_dir_listing", "dir", "latest", None),
)


@dataclass(frozen=True)
class SQL:
    get_pkgset_packages = """
WITH
(
    SELECT pkgset_uuid
    FROM PackageSetName
    WHERE pkgset_nodename = 'srpm'
        AND pkgset_ruuid IN
    (
        SELECT pkgset_uuid
        FROM PackageSetName
        WHERE pkgset_depth = 0
            AND pkgset_nodename = %(branch)s
            AND pkgset_date = %(date)s
    )
) AS src_uuid
SELECT
    pkg_hash,
    pkg_name,
    pkg_version,
    pkg_release
FROM Packages
WHERE pkg_sourcepackage = 1
    AND pkg_hash IN
    (
        SELECT pkg_hash
        FROM PackageSet
        WHERE pkgset_uuid = src_uuid
    )
"""

    get_recent_pkgset_date = """
SELECT * FROM
(
    SELECT max(pkgset_date) AS date
    FROM PackageSetName
    WHERE pkgset_nodename = %(branch)s
        AND pkgset_date < %(date)s
)
WHERE date > '2000-01-01'
"""

    get_all_packages_versions = """
WITH
    pkg_packages AS
    (
        SELECT
            pkg_hash,
            pkg_name,
            pkg_version,
            pkg_release
        FROM Packages
        WHERE (pkg_name IN %(packages)s) AND (pkg_sourcepackage = 1)
    ),
    pkg_tasks AS
    (
        SELECT DISTINCT
            task_id,
            titer_srcrpm_hash
        FROM TaskIterations
        WHERE titer_srcrpm_hash IN (
            SELECT pkg_hash
            FROM pkg_packages
        )
    )
SELECT DISTINCT
    pkg_tasks.task_id,
    pkg_tasks.titer_srcrpm_hash,
    TSK.task_repo,
    PKG.*
FROM pkg_tasks
LEFT JOIN
(
    SELECT
        task_id,
        task_repo
    FROM Tasks
) AS TSK ON TSK.task_id = pkg_tasks.task_id
LEFT JOIN
(
    SELECT *
    FROM pkg_packages
) AS PKG ON pkg_hash = titer_srcrpm_hash
WHERE TSK.task_repo = %(branch)s
ORDER BY pkg_tasks.task_id ASC
"""

    get_last_beehive_changed = """
SELECT
    pkgset_name,
    bh_arch,
    max(bh_updated)
FROM BeehiveStatus
GROUP BY
    pkgset_name,
    bh_arch
"""

    insert_into_beehive_status = """
INSERT INTO BeehiveStatus (*) VALUES
"""

def get_client(args: object) -> Client:
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


def get_args() -> object:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    args = parser.parse_args()

    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            args.dbname = args.dbname or section_db.get("dbname", "default")
            args.host = args.host or section_db.get("host", "localhost")
            args.port = args.port or section_db.get("port", None)
            args.user = args.user or section_db.get("user", "default")
            args.password = args.password or section_db.get("password", "")
    else:
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""

    return args


def tuples_list_to_dict(x: list) -> dict:
    res = {}
    for el in x:
        res[int(el[0])] = tuple(el[1:])

    return res


def dump_to_json(content: dict, prefix: str) -> None:
    p = Path.joinpath(Path.cwd(), "JSON")
    p.mkdir(exist_ok=True)
    Path.joinpath(p, f"dump-{prefix}.json").write_text(
        json.dumps(content, indent=2, sort_keys=True, default=str)
    )


class Beehive:
    def __init__(
        self,
        base_url: str,
        branches: tuple,
        archs: tuple,
        endpoints: list[Endpoint],
        conn: Client,
        timeout: int,
    ) -> None:
        self.base_url = base_url
        self.branches = branches
        self.archs = archs
        self.endpoints = endpoints
        self.sql = SQL()
        self.conn = conn
        self.timeout = timeout
        self.targets = self._build_beehive_targets_list()
        self.beehive = {}

    @staticmethod
    def _parse_name_evr(pkg: str) -> Package:
        """Parse package file name to Package(name, version, release)."""

        if pkg.endswith(".src.rpm"):
            pkg = pkg.replace(".src.rpm", "")
        evr = pkg.split("-")[-2:]
        if len(evr) == 2 and evr[1].startswith("alt"):
            version, release = evr
        else:
            version = release = ""
        #  delete epoch from version
        if ":" in version:
            version_ = version.split(":")[1]
        else:
            version_ = version
        name = pkg.replace(f"-{version}-{release}", "")
        return Package(name, version_, release)

    def _build_beehive_targets_list(self) -> list[Target]:
        targets = []
        for branch in self.branches:
            for arch in self.archs:
                for endpoint in self.endpoints:
                    url = "/".join((self.base_url, branch, arch, endpoint.path))
                    targets.append(
                        Target(
                            branch,
                            arch,
                            endpoint.name,
                            endpoint.type,
                            url,
                            endpoint.destination,
                        )
                    )
        return targets

    def _get_content(self, target: Target) -> list:
        def process_package_listing_item(x):
            return PackageInfo(
                self._parse_name_evr(x.name),
                datetime.datetime(*x.modified[0:6]),
                x.size,
            )

        def process_file_listing_item(x):
            return FileInfo(x.name, datetime.datetime(*x.modified[0:6]), x.size)

        try:
            destination = target.destination
            if target.type == "file":
                response = requests.get(target.url, timeout=self.timeout)
                response.raise_for_status()
                # return parsed file contents
                lines = []
                for line in response.text.splitlines():
                    line_context = line.split("\t")[:2]
                    lines.append(
                        (self._parse_name_evr(line_context[0]), float(line_context[1]))
                    )
                return target, lines
            else:
                _, listing = fetch_listing(target.url, timeout=self.timeout)
                if destination:
                    matches = []
                    if isinstance(destination, str):
                        for file_ in listing:
                            if file_.name == destination:
                                matches.append(process_file_listing_item(file_))
                                break
                    if isinstance(destination, (list, tuple)):
                        for file_ in listing:
                            if file_.name in destination:
                                matches.append(process_file_listing_item(file_))
                    return target, matches
                else:
                    files = [process_package_listing_item(f) for f in listing]
                    return target, files
        except Exception as e:
            if issubclass(e.__class__, HTTPError):
                log.info(f"Failed to get url {target.url}")
                return target, []
            else:
                raise e

    def _get_beehive_build_status(self, t_key: TargetKey, result_type: str) -> set:
        if result_type == "error":
            t_key = t_key._replace(name="error_dir_listing")
        elif result_type == "success":
            t_key = t_key._replace(name="success_dir_listing")
        else:
            raise ValueError(f"Unknown result_type {result_type}")

        if t_key not in self.beehive:
            log.error("Target not found in Beehive")
            raise ValueError(f"Wrong target key {t_key}")

        return {el[0] for el in self.beehive[t_key]}

    def _get_beehive_build_time(self, t_key: TargetKey) -> dict:
        if t_key not in self.beehive:
            log.error("Target not found in Beehive")
            raise ValueError(f"Wrong target key {t_key}")

        return {el[0]: el[1] for el in self.beehive[t_key]}

    def _get_latest_mtime(self, t_key: TargetKey) -> datetime.datetime:
        t_key = t_key._replace(name="latest_dir_mtime")
        mtime = self.beehive[t_key][0].modified.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return mtime

    def _get_last_beehive_status_from_db(self) -> dict:
        # FIXME: use self.conn when production database ready
        conn = Client(
            "10.88.13.52",
            port=9000,
            database="repodb",
            user='default',
            password='',
        )
        conn.connection.connect()
        res = conn.execute(self.sql.get_last_beehive_changed)
        last_bh_updated = {(el[0], el[1]): el[2] for el in res}
        # FIXME: do not disconnect if use self.conn
        conn.disconnect()

        return last_bh_updated

    def _get_packages_from_db(self, t_key: TargetKey) -> dict[Package]:
        modified = self._get_latest_mtime(t_key)

        log.info(f"Query packages for {t_key.branch} on date {modified} from DB")
        sql_res = self.conn.execute(
            self.sql.get_pkgset_packages,
            params={"branch": t_key.branch, "date": modified},
        )
        log.debug(f"SQL request elapsed {self.conn.last_query.elapsed:.3f} seconds")

        packages_from_db = {Package(*el[1:]): int(el[0]) for el in sql_res}

        if not packages_from_db:
            log.info(f"No data found in DB for {t_key.branch} on date {modified}")
            # try to find and load the latest repository state prior to Beehive date
            log.info(f"Query recent loaded date for {t_key.branch} from DB")
            sql_res = self.conn.execute(
                self.sql.get_recent_pkgset_date,
                params={"branch": t_key.branch, "date": modified},
            )
            log.debug(f"SQL request elapsed {self.conn.last_query.elapsed:.3f} seconds")
            if not sql_res:
                log.error(f"Failed to find recent lodaded date for {t_key.branch} in DB")
                return {}
            modified = sql_res[0][0]
            # load packages from recent repository state
            log.info(f"Query packages for {t_key.branch} on date {modified} from DB")
            sql_res = self.conn.execute(
                self.sql.get_pkgset_packages,
                params={"branch": t_key.branch, "date": modified},
            )
            log.debug(f"SQL request elapsed {self.conn.last_query.elapsed:.3f} seconds")

            packages_from_db = {Package(*el[1:]): int(el[0]) for el in sql_res}

        return packages_from_db

    def _get_missing_packages_infor_from_db(
        self, t_key: TargetKey, packages: list[Package]
    ) -> dict[Package]:
        branch = t_key.branch
        #  convert list of packages to set for fast searching
        packages = set(packages)
        log.info(f"Query packages from DB")
        sql_res = self.conn.execute(
            self.sql.get_all_packages_versions,
            params={"packages": [pkg.name for pkg in packages], "branch": branch},
        )
        log.debug(f"SQL request elapsed {self.conn.last_query.elapsed:.3f} seconds")

        if not sql_res:
            log.error(f"No data found in DB for {packages}")
            return {}
        log.info(f"Found {len(sql_res)} packages from DB")

        res = {}
        for hsh, pkg in {(int(el[3]), Package(*el[4:])) for el in sql_res}:
            if pkg in packages:
                res[pkg] = hsh

        return res

    @staticmethod
    def _compare_beehive_with_db(
        t_key: TargetKey, packages_from_beehive: dict, packages_from_db: dict
    ) -> tuple[list, list]:
        pkgs_from_db = set(packages_from_db.keys())
        pkgs_from_beehive = set(packages_from_beehive.keys())

        if not packages_from_db:
            log.info(f"Empty 'packages_from_db' list. Exiting..")
            return [], []

        if not pkgs_from_beehive:
            log.info(f"Empty 'pkgs_from_beehive' list. Exiting..")
            return [], []

        pkgs_missing = []
        for pkg in pkgs_from_db:
            if pkg not in pkgs_from_beehive:
                pkgs_missing.append(pkg)
        log.info(
            f"{len(pkgs_missing)} packages from DB are not in {t_key.branch}/{t_key.arch} files from Beehive"
        )

        mismatched_packages = []
        not_found_packages = []
        log.info(f"Check packages from beehive that are not in DB")
        for pkg in pkgs_from_beehive:
            if pkg not in pkgs_from_db:
                log.info(f"Package {pkg} not found in DB")
                name_matched = False
                for pkg2 in pkgs_from_db:
                    if pkg2.name == pkg.name:
                        log.info(
                            f"Missing package name matched: Beehive: {pkg} DB: {pkg2}"
                        )
                        mismatched_packages.append(pkg)
                        name_matched = True
                        break
                if not name_matched:
                    log.info(
                        f"Package {pkg} from Beehive not found in packages from DB"
                    )
                    not_found_packages.append(pkg)

        return mismatched_packages, not_found_packages

    def _store_beehive_results(
        self,
        t_key: TargetKey,
        pkgs_time: dict,
        pkgs_success: set,
        pkgs_error: set,
        pkgs_from_db: dict,
    ) -> None:
        mtime = self._get_latest_mtime(t_key)
        result: list[dict] = []
        for pkg, b_time in pkgs_time.items():
            el_dict = {
                "pkg_hash": None,
                "pkg_name": pkg.name,
                "pkg_version": pkg.version,
                "pkg_release": pkg.release,
                "pkgset_name": t_key.branch,
                "bh_arch": t_key.arch,
                "bh_status": None,
                "bh_build_time": b_time,
                "bh_updated": cvt_datetime_local_to_utc(mtime),
            }

            if pkg in pkgs_success:
                el_dict["bh_status"] = "success"
            elif pkg in pkgs_error:
                el_dict["bh_status"] = "error"
            else:
                log.error(f"Failed to get status for package {pkg}. Element: {el_dict}")
                raise ValueError("Can't find package build status")

            try:
                el_dict["pkg_hash"] = pkgs_from_db[pkg]
            except KeyError:
                log.error(f"Failed to get hash for package {pkg}. Element: {el_dict}")
                raise ValueError("Can't find package hash")

            result.append(el_dict)

        ### DEBUG BEGIN ###
        # FIXME: remove from final version or use separate option to turn on
        dump_to_json(result, f"{mtime.strftime('%Y-%m-%d')}_{t_key.branch}_{t_key.arch}")
        # FIXME: use self.conn when production database ready
        conn = Client(
            "10.88.13.52",
            port=9000,
            database="repodb",
            user='default',
            password='',
        )
        conn.connection.connect()
        conn.execute(self.sql.insert_into_beehive_status, result)
        # FIXME: do not disconnect if use self.conn
        conn.disconnect()
        ### DEBUG END ###
        log.info(f"Data for {t_key.branch}/{t_key.arch} inserted to DB")


    def beehive_store(self) -> None:
        latest_beehive_from_db = self._get_last_beehive_status_from_db()
        for branch_ in self.branches:
            branch = branch_.lower()
            for arch in self.archs:
                t_key = TargetKey(branch, arch, "time_file_listing")
                # check if target contents were loaded from Beehive
                if t_key not in self.beehive:
                    continue

                log.info(f"Processing data for {branch_}/{arch}")

                pkgs_time = self._get_beehive_build_time(t_key)

                # check if beehive result already loaded to DB
                mtime = self._get_latest_mtime(t_key)
                mtime_from_db = latest_beehive_from_db.get((branch, arch), None)
                if mtime == mtime_from_db:
                    log.info(f"Data for {branch_}/{arch} on {mtime} already loaded to DB")
                    continue

                if not pkgs_time:
                    log.error(f"No package build time info found from Beehive for {branch_}/{arch}")
                    raise RuntimeError("No data found from beehive")
                    # continue
                log.info(f"Found {len(pkgs_time)} packages from Beehive")

                pkgs_from_db = self._get_packages_from_db(t_key)
                if not pkgs_from_db:
                    # error logged already in self._get_packages_from_db()
                    # raise RuntimeError("No data found from beehive")
                    continue
                log.info(f"Found {len(pkgs_from_db)} packages from DB")

                miss, nf = self._compare_beehive_with_db(t_key, pkgs_time, pkgs_from_db)
                log.debug(f"Missmatched packages: {miss}")
                log.debug(f"Not found packages: {nf}")

                if miss + nf:
                    res = self._get_missing_packages_infor_from_db(
                        t_key=t_key, packages=(miss + nf)
                    )
                    pkgs_from_db.update(res)

                if len(pkgs_time) > len(pkgs_from_db):
                    log.error(
                        f"Inconsistent data from Beehive and form DB for {branch_}/{arch}"
                    )
                    break

                pkgs_success = self._get_beehive_build_status(
                    t_key=t_key, result_type="success"
                )
                pkgs_error = self._get_beehive_build_status(
                    t_key=t_key, result_type="error"
                )
                pkgs_status = pkgs_success | pkgs_error

                if len(pkgs_time) != len(pkgs_status):
                    log.error(
                        f"Inconsistent data from Beehive for {branch_}/{arch}"
                    )
                    break

                self._store_beehive_results(
                    t_key, pkgs_time, pkgs_success, pkgs_error, pkgs_from_db
                )

    def beehive_load(self) -> None:
        for target in self.targets:
            log.info(f"Fetching data from {target.url}")
            target, result = self._get_content(target)
            key = TargetKey(target.branch.lower(), target.arch, target.name)
            if result:
                self.beehive[key] = result


def load(args: object, conn: Client) -> None:
    bh = Beehive(
        base_url=BEEHIVE_BASE_URL,
        branches=BEEHIVE_BRANCHES,
        archs=BEEHIVE_ARCHS,
        endpoints=BEEHIVE_ENDPOINTS,
        conn=conn,
        timeout=30,
    )
    bh.beehive_load()
    bh.beehive_store()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="load")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        conn.connection.connect()
        load(args, conn)
    except Exception as error:
        logger.exception("Error occurred during Beehive information loading.")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
