# This file is part of the altrpm distribution (http://git.altlinux.org/people/dshein/public/altrpm.git).
# Copyright (c) 2021-2022 BaseALT Ltd
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

from .rpm import RPMHeaders, RPMCpio
from .rpm import parse_headers_list, parse_xz_headers_list
from .rpmtag import rpmh as rpm

VERSION = (0, 2, 0)
__version__ = ".".join(str(x) for x in VERSION)

__all__ = [
    "readHeaderFromRPM",
    "readHeaderListFromFile",
    "readHeaderListFromXZFile",
    "extractSpecFromRPM",
    "extractSpecAndHeadersFromRPM",
    "rpm",
]


def readHeaderFromRPM(filename):
    """Reads RPM file headers and parses it to dictionary.

    Args:
        filename (str|path): filename or path-like object

    Returns:
        dict: parsed RPM headers dictionary
    """
    rpm = RPMHeaders(filename)
    return rpm.parse_headers()


def readHeaderListFromFile(filename):
    """Reads RPM headers list file and parses it to list of headers dictionaries.

    Args:
        filename (str|path): filename or path-like object

    Returns:
        list: list of parsed headers dictionaries
    """

    return parse_headers_list(filename)


def readHeaderListFromXZFile(filename):
    """Reads XZ compressed RPM headers list file and parses it to list of headers dictionaries.

    Args:
        filename (str|path): filename or path-like object

    Returns:
        list: list of parsed headers dictionaries
    """

    return parse_xz_headers_list(filename)


def extractSpecFromRPM(filename, raw):
    """Extracts spec file from RPM package.

    Args:
        filename (str|path): filename or path-like object
        raw (bool): return spec file contents as raw bytes or decode to UTF-8

    Returns:
        tuple: spec file archive entry, spec file contents
    """
    rpm = RPMCpio(filename)
    return rpm.extract_spec_file(raw=raw)


def extractSpecAndHeadersFromRPM(filename, raw):
    """Extracts spec file and headers from RPM package.

    Args:
        filename (str|path): filename or path-like object
        raw (bool): return spec file contents as raw bytes or decode to UTF-8

    Returns:
        tuple: spec file archive entry, spec file contents, headers dictionary
    """
    rpm = RPMCpio(filename)
    return *rpm.extract_spec_file(raw=raw), rpm.hdr
