# This file is part of the altrpm distribution (http://git.altlinux.org/people/dshein/public/altrpm.git).
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

import io
import os
import bz2
import gzip
import lzma
import shutil
import struct
from struct import error as StructError
import libarchive
import subprocess
from collections import namedtuple
from typing import Union, BinaryIO, Any

from .rpmtag import rpmh, rpms, rpmt, rpmtt, get_tag_content

USE_COMPRESSOR_MAGIC = True
USE_DEFAULT_C_LOCALE = True

RPM_MAGIC = b"\xED\xAB\xEE\xDB"
RPM_HEADER_MAGIC = b"\x8E\xAD\xE8"

lead_struct = struct.Struct("!4sBBhh66shh16s")
header_struct = struct.Struct("!3s1b4sii")
tag_struct = struct.Struct("!iiii")

RPMLeadS = namedtuple(
    "RPMLeadS",
    ["magic", "major", "minor", "type", "archnum", "name", "osnum", "sig_type"],
)
RPMHeaderRecordS = namedtuple(
    "RPMHeaderRecordS", ["magic", "version", "reserved", "nindex", "hsize"]
)
RPMTagS = namedtuple("RPMTagS", ["tag", "type", "offset", "count"])
File = namedtuple("File", ["attrs", "content"])


def decompress_none(fileobj: BinaryIO):
    return fileobj.read


def decompress_gzip(fileobj):
    reader = gzip.GzipFile(fileobj=fileobj)
    return reader.read


def decompress_bzip2(fileobj):
    reader = bz2.open(fileobj, "rb")
    return reader.read


def decompress_lzma(fileobj):
    reader = lzma.open(fileobj, "rb")
    return reader.read


def decompress_zstd(fileobj):
    decompressor = subprocess.Popen(
        ["unzstd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    return io.BytesIO(decompressor.communicate(input=fileobj.read())[0]).read


decompressors: dict = {
    b"gzip": decompress_gzip,
    b"lzma": decompress_lzma,
    b"xz": decompress_lzma,
    b"zstd": decompress_zstd,
    b"bzip2": decompress_bzip2,
}

compressors_magic: dict = {
    b"\x42\x5a": decompress_bzip2,
    b"\x1f\x8b": decompress_gzip,
    b"\xfd\x37": decompress_lzma,
    b"\x5d\x00": decompress_lzma,
    b"\x28\xb5": decompress_zstd,
    b"\x30\x37": decompress_none,
}


def bytes2integer(data: bytes, order: str = "big") -> int:
    return int.from_bytes(data, order)


def extract_bin(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> bytes:
    pos_ = reader.tell()
    reader.seek(base + offset)
    data = reader.read(count)
    if rewind:
        reader.seek(pos_)
    return data


def extract_char(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> bytes:
    count = 1
    return extract_bin(reader, base, offset, count, rewind)


def extract_int(
    reader: BinaryIO, base: int, offset: int, count: int, width: int, rewind: bool
) -> list[int]:
    pos_ = reader.tell()
    reader.seek(base + offset)
    data = reader.read(count * width)
    values = [bytes2integer(data[i * width : (i + 1) * width]) for i in range(count)]
    if rewind:
        reader.seek(pos_)
    return values


def extract_int8(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> list[int]:
    return extract_int(reader, base, offset, count, 1, rewind)


def extract_int16(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> list[int]:
    return extract_int(reader, base, offset, count, 2, rewind)


def extract_int32(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> list[int]:
    return extract_int(reader, base, offset, count, 4, rewind)


def extract_int64(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> list[int]:
    return extract_int(reader, base, offset, count, 8, rewind)


def extract_array(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> list[bytes]:
    BUFF_SIZE = 256
    pos_ = reader.tell()
    reader.seek(base + offset)
    data = []
    for _ in range(count):
        st_start_ = reader.tell()
        buff_ = reader.read(BUFF_SIZE)
        if not buff_:
            break
        while True:
            st_end_ = buff_.find(b"\x00")
            if st_end_ == -1:
                buff_ += reader.read(BUFF_SIZE)
            if st_end_ == 0:
                data.append(b"")
                reader.seek(st_start_ + 1)
                break
            if st_end_ > 0:
                data.append(buff_[0:st_end_])
                reader.seek(st_start_ + st_end_ + 1)
                break
    if rewind:
        reader.seek(pos_)
    return data


def extract_string(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> bytes:
    count = 1
    return extract_array(reader, base, offset, count, rewind)[0]


extractors = {
    rpmt.RPM_BIN_TYPE: extract_bin,
    rpmt.RPM_CHAR_TYPE: extract_char,
    rpmt.RPM_INT8_TYPE: extract_int8,
    rpmt.RPM_INT16_TYPE: extract_int16,
    rpmt.RPM_INT32_TYPE: extract_int32,
    rpmt.RPM_INT64_TYPE: extract_int64,
    rpmt.RPM_STRING_TYPE: extract_string,
    rpmt.RPM_STRING_ARRAY_TYPE: extract_array,
    rpmt.RPM_I18NSTRING_TYPE: extract_array,
}


def bytes2string(fileobj, encoding="utf-8"):
    data = extract_string(fileobj, 0, 1, 1, rewind=False)
    return data.decode(encoding)


class Object(object):
    pass


class RPMHeadersDict(dict):
    def __init__(self):
        return super().__init__()

    def __getitem__(self, key):
        return get_tag_content(super(), key)


class RPMHeaderParser:
    def __init__(self, reader: BinaryIO, from_headers_list=False):
        self.from_headers_list = from_headers_list
        self.reader = reader
        self.hdr = RPMHeadersDict()
        self.hdr_base = 0
        self.hdr_contents_base = 0
        self.sig_hdr_dict = {}
        self.sig_hdr_base = 0
        self.sig_hdr_contents_base = 0
        self.compressed_payload_offset = 0
        self.parse_headers()

    def extract_tag_content(self, rpm_tag: RPMTagS, is_sig_tag=False):
        if is_sig_tag:
            base = self.sig_hdr_contents_base
        else:
            base = self.hdr_contents_base
        data = extractors[rpm_tag.type](
            self.reader, base, rpm_tag.offset, rpm_tag.count, rewind=True
        )

        tag_id = rpms[rpm_tag.tag] if is_sig_tag else rpm_tag.tag

        if tag_id is not None:
            # convert tag data representation in accordance to it's type
            if rpmtt[tag_id] == rpmtt.ANY and isinstance(data, list):
                data = data[0]
            # convert I18N tags to return only 'C' locale
            elif (
                USE_DEFAULT_C_LOCALE
                and rpmtt[tag_id] == rpmtt.LOCALE_STRING_ARRAY
                and isinstance(data, list)
            ):
                data = data[0]
            self.hdr[tag_id] = data

    def parse_headers(self):
        is_binary_pkg = True
        # headers list file does not contains lead and signature
        if not self.from_headers_list:
            # read lead
            rpm_lead = lead_struct.unpack(self.reader.read(lead_struct.size))
            if rpm_lead[0] != RPM_MAGIC:
                raise ValueError(f"File is not a RPM package")

            # set package type flag from 'type' field in lead section 
            if rpm_lead[3] != 0:
                is_binary_pkg = False

            # read signature Header Record
            sig_start = self.reader.tell()
            rpm_sig = RPMHeaderRecordS(
                *header_struct.unpack(self.reader.read(header_struct.size))
            )
            if rpm_sig.magic != RPM_HEADER_MAGIC:
                raise ValueError("RPM Header Record not found")

            self.sig_hdr_base = sig_start
            self.sig_hdr_contents_base = sig_start + 16 + rpm_sig.nindex * 16

            # processing rpm signature header tags here
            for _ in range(rpm_sig.nindex):
                rpm_tag = RPMTagS(*tag_struct.unpack(self.reader.read(tag_struct.size)))
                self.extract_tag_content(rpm_tag, is_sig_tag=True)

            # get RPM Signature structure end
            sig_header_size = 16 * rpm_sig.nindex + rpm_sig.hsize + 16

            # rpm signature should be alligned to 8 bytes boundary
            offset = sig_start + sig_header_size + (8 - (sig_header_size % 8)) % 8
            self.reader.seek(offset)

        # read RPM tags Header Record
        hdr_start = self.reader.tell()
        rpm_header = RPMHeaderRecordS(
            *header_struct.unpack(self.reader.read(header_struct.size))
        )
        if rpm_header.magic != RPM_HEADER_MAGIC:
            raise ValueError("RPM Header Record not found")

        hdr_data_offset_base = hdr_start + 16 + rpm_header.nindex * 16

        self.hdr_base = hdr_start
        self.hdr_contents_base = hdr_data_offset_base
        self.compressed_payload_offset = hdr_data_offset_base + rpm_header.hsize

        # processing rpm header tags here
        for _ in range(rpm_header.nindex):
            rpm_tag = RPMTagS(*tag_struct.unpack(self.reader.read(tag_struct.size)))
            self.extract_tag_content(rpm_tag, is_sig_tag=False)
        
        # set RPMTAG_SOURCEPACKAGE in librpm way
        if not is_binary_pkg and self.hdr[rpmh.RPMTAG_SOURCERPM] is None:
            self.hdr[rpmh.RPMTAG_SOURCEPACKAGE] = 1



def parse_headers_list(filename):
    with open(filename, "rb") as f:
        hdrs = []
        while True:
            try:
                parser = RPMHeaderParser(f, from_headers_list=True)
                hdrs.append(parser.hdr)
                f.seek(parser.compressed_payload_offset)
            except (ValueError, StructError):
                break
        return hdrs


def parse_xz_headers_list(filename):
    # uncompress and read headers from list
    r, w = os.pipe()
    r, w = os.fdopen(r, "rb", 0), os.fdopen(w, "wb", 0)
    pid = os.fork()
    if pid:  # Parser
        w.close()
        hdrs_file = io.BytesIO(r.read())
        r.close()

        hdrs = []
        while True:
            try:
                parser = RPMHeaderParser(hdrs_file, from_headers_list=True)
                hdrs.append(parser.hdr)
                hdrs_file.seek(parser.compressed_payload_offset)
            except (ValueError, StructError):
                break
        hdrs_file.close()
        return hdrs
    else:  # Decompressor
        r.close()
        fdno = lzma.open(filename, "rb")
        shutil.copyfileobj(fdno, w)
        os._exit(0)


_FileOrPath = Union[str, bytes, os.PathLike]


class RPMHeaders:
    def __init__(self, rpm_file: _FileOrPath):
        self.hdrs = RPMHeadersDict()
        self.rpm_file = rpm_file

    def parse_headers(self):
        with io.open(self.rpm_file, "rb") as f:
            parser = RPMHeaderParser(f, from_headers_list=False)
            self.hdrs = parser.hdr
        return self.hdrs


class RPMCpio(RPMHeaderParser):
    def __init__(self, rpm_file: _FileOrPath):
        self.rpm_file = rpm_file
        self.reader: Any = None
        self.payload_compressor = None
        self.compressed_payload_offset = 0
        self._open()
        super().__init__(self.reader)

    def __del__(self):
        self._close()

    def _open(self):
        if not self.reader:
            self.reader = io.open(self.rpm_file, "rb")

    def _close(self):
        if self.reader:
            self.reader.close()

    def _get_payload_compressor_by_magic(self):
        pos_ = self.reader.tell()
        magic = self.reader.read(2)
        self.reader.seek(pos_)
        return compressors_magic.get(magic, None), magic

    def _extract_cpio(self):
        self.reader.seek(self.compressed_payload_offset)

        if not USE_COMPRESSOR_MAGIC:
            # get payload compressor form tag #1125
            self.payload_compressor = self.hdr[rpmh.RPMTAG_PAYLOADCOMPRESSOR]

            if self.payload_compressor is None:
                decompressor = decompress_none

            decompressor = decompressors.get(self.payload_compressor, None)
            if decompressor is None:
                raise NotImplementedError(
                    f"Decompressor not found for romat {self.payload_compressor}"
                )
        else:
            decompressor, magic = self._get_payload_compressor_by_magic()
            if decompressor is None:
                raise NotImplementedError(
                    f"Decompressor not found for signature {magic}"
                )

        return decompressor(self.reader)

    @staticmethod
    def _copy_file_attrs(file_entry, dst_obj):
        attrs = (
            "filetype",
            "uid",
            "gid",
            "isblk",
            "ischr",
            "isfifo",
            "islnk",
            "issym",
            "linkpath",
            "linkname",
            "isreg",
            "isfile",
            "issock",
            "isdev",
            "atime",
            "mtime",
            "ctime",
            "birthtime",
            "path",
            "name",
            "size",
            "mode",
            "strmode",
            "rdevmajor",
            "rdevminor",
        )
        for attr in attrs:
            setattr(dst_obj, attr, getattr(file_entry, attr, None))

    def extract_spec_file(self, raw=True):
        # read cpio content and search for '*.spec' file
        self._open()

        spec_file_contents = b""
        spec_file = Object()
        with libarchive.memory_reader(self._extract_cpio()()) as archive:
            for entry in archive:
                if entry.isfile and (
                    entry.name.endswith(".spec") or entry.name == "spec"
                ):
                    self._copy_file_attrs(entry, spec_file)
                    for block in entry.get_blocks():
                        spec_file_contents += block
                    break

        self._close()

        if not hasattr(spec_file, "name"):
            raise KeyError("Spec file entry not found in CPIO contents")

        if raw:
            return spec_file, spec_file_contents
        else:
            return spec_file, spec_file_contents.decode(
                "utf-8", errors="backslashreplace"
            )

    def extract_cpio_raw(self):
        self._open()
        data = self._extract_cpio()()
        self._close()
        return data

    def extract_cpio_files(self):
        files = []
        self._open()

        file_contents_ = b""
        file_ = Object()
        with libarchive.memory_reader(self._extract_cpio()()) as archive:
            for entry in archive:
                file_contents_ = b""
                file_ = Object()
                self._copy_file_attrs(entry, file_)
                for block in entry.get_blocks():
                    file_contents_ += block
                files.append(File(file_, file_contents_))

        self._close()

        return files
