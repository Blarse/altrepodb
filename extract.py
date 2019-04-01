import os
import rpm
import psycopg2


map_db2tag = {
    # PackageBin ->
    "name": rpm.RPMTAG_NAME,
    "arch": rpm.RPMTAG_ARCH,
    "version": rpm.RPMTAG_VERSION,
    "release": rpm.RPMTAG_RELEASE,
    "epoch": rpm.RPMTAG_EPOCH,
    "serial_": rpm.RPMTAG_SERIAL,
    "summary": rpm.RPMTAG_SUMMARY,
    "description": rpm.RPMTAG_DESCRIPTION,
    "buildtime": rpm.RPMTAG_BUILDTIME,
    "buildhost": rpm.RPMTAG_BUILDHOST,
    "size": rpm.RPMTAG_SIZE,
    "distribution": rpm.RPMTAG_DISTRIBUTION,
    "vendor": rpm.RPMTAG_VENDOR,
    "gif": rpm.RPMTAG_GIF,
    "xpm": rpm.RPMTAG_XPM,
    "license": rpm.RPMTAG_LICENSE,
    "group_": rpm.RPMTAG_GROUP,
    "source": rpm.RPMTAG_SOURCE,
    "patch": rpm.RPMTAG_PATCH,
    "url": rpm.RPMTAG_URL,
    "os": rpm.RPMTAG_OS,
    "prein": rpm.RPMTAG_PREIN,
    "postin": rpm.RPMTAG_POSTIN,
    "preun": rpm.RPMTAG_PREUN,
    "postun": rpm.RPMTAG_POSTUN,
    "icon": rpm.RPMTAG_ICON,
    "archivesize": rpm.RPMTAG_ARCHIVESIZE,
    "rpmversion": rpm.RPMTAG_RPMVERSION,
    "preinprog": rpm.RPMTAG_PREINPROG,
    "postinprog": rpm.RPMTAG_POSTINPROG,
    "preunprog": rpm.RPMTAG_PREUNPROG,
    "postunprog": rpm.RPMTAG_POSTUNPROG,
    "buildarchs": rpm.RPMTAG_BUILDARCHS,
    "verifyscript": rpm.RPMTAG_VERIFYSCRIPT,
    "verifyscriptprog": rpm.RPMTAG_VERIFYSCRIPTPROG,
    "cookie": rpm.RPMTAG_COOKIE,
    "prefixes": rpm.RPMTAG_PREFIXES,
    "instprefixes": rpm.RPMTAG_INSTPREFIXES,
    "sourcepackage": rpm.RPMTAG_SOURCEPACKAGE,
    "optflags": rpm.RPMTAG_OPTFLAGS,
    "disturl": rpm.RPMTAG_DISTURL,
    "payloadformat": rpm.RPMTAG_PAYLOADFORMAT,
    "payloadcompressor": rpm.RPMTAG_PAYLOADCOMPRESSOR,
    "payloadflags": rpm.RPMTAG_PAYLOADFLAGS,
    "platform": rpm.RPMTAG_PLATFORM,
    "sourcepkgid": rpm.RPMTAG_SOURCEPKGID,
    "disttag":rpm.RPMTAG_DISTTAG,
    # <- PackageBin
}


def get_info(h):
    pass


def save_info(data):
    pass


def find_packages(path):
    for dirname, _, filenames in os.walk(path):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.rpm') and not os.path.islink(f):
                yield f


def get_head(ts, rpm_file):
    f = os.open(rpm_file, os.O_RDONLY)
    h = ts.hdrFromFdno(f)
    os.close(f)
    return h


def load():
    ts = rpm.TransactionSet()
    fp = find_packages('/mnt/repo/Sisyphus/files/')
    for c, i in enumerate(fp):
        h = get_head(ts, i)
        for k, v in map_db2tag.items():
            print("Name: {0}; Value: {1}".format(k, h[v]))
        if c == 10:
            break
        print("\n\n")


def main():
    # load()
    # s = ", ".join(map_db2tag.keys())
    # v = ", ".join(["%s"] * len(map_db2tag))
    # print("INSERT INTO packagebin ({0}) VALUES ({1})".format(s, v))
    conn = psycopg2.connect("dbname=repodb user=underwit")
    cur = conn.cursor()
    print(conn, cur)
    cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'packagebin';")
    print(cur.fetchall())
        


if __name__ == '__main__':
    main()
