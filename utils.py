import datetime

def cvt(b):
    if isinstance(b, bytes):
        return b.decode('latin-1')
    if isinstance(b, list):
        return [cvt(i) for i in b]
    return b


def changelog_date_format(ts):
    dt = datetime.date.fromtimestamp(ts)
    return dt.strftime("%a %b %d %Y")


def cvt_ts(ts):
    if isinstance(ts, int):
        return datetime.datetime.fromtimestamp(ts)
    if isinstance(ts, list):
        return [cvt_ts(i) for i in ts]
    return ts


def changelog_to_text(dates, names, texts):
    if not len(dates) == len(names) == len(texts):
        raise ValueError
    text = ""
    for d, n, t in zip(dates, names, texts):
        text += "* {0} {1}\n{2}\n\n".format(changelog_date_format(d), cvt(n), cvt(t))
    return text
