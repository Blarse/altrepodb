import io
import bz2
import gzip
import lzma
from os import PathLike
import struct
from struct import error as StructError
import libarchive
import subprocess
from collections import namedtuple
from typing import Union, BinaryIO, Any

from .rpmtag import rpmh, rpms, rpmt, RPMHeaderExtractor

USE_COMPRESSOR_MAGIC = True

RPM_MAGIC = b"\xED\xAB\xEE\xDB"
RPM_HEADER_MAGIC = b"\x8E\xAD\xE8"

lead_struct = struct.Struct(b"!4sBBhh66shh16s")
header_struct = struct.Struct(b"!3s1b4sii")
tag_struct = struct.Struct(b"!iiii")

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
) -> Union[int, list[int]]:
    data = extract_int(reader, base, offset, count, 1, rewind)
    if count == 1:
        return data[0]
    return data


def extract_int16(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> Union[int, list[int]]:
    data = extract_int(reader, base, offset, count, 2, rewind)
    if count == 1:
        return data[0]
    return data


def extract_int32(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> Union[int, list[int]]:
    data = extract_int(reader, base, offset, count, 4, rewind)
    if count == 1:
        return data[0]
    return data


def extract_int64(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> Union[int, list[int]]:
    data = extract_int(reader, base, offset, count, 8, rewind)
    if count == 1:
        return data[0]
    return data


def extract_array(
    reader: BinaryIO, base: int, offset: int, count: int, rewind: bool = False
) -> list[bytes]:
    pos_ = reader.tell()
    reader.seek(base + offset)
    data = []
    for _ in range(count):
        chars = b""
        while True:
            c = reader.read(1)
            if c == b"\x00":
                data.append(chars)
                break
            chars += c
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
        self.he = RPMHeaderExtractor()
        return super().__init__()

    def __getitem__(self, key):
        return self.he.get_tag_content(key, super())


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

        tag_name = rpms[rpm_tag.tag] if is_sig_tag else rpmh[rpm_tag.tag]

        if tag_name is None:
            tag_name = f"TAG_{str(rpm_tag.tag)}"

        self.hdr[tag_name] = data

    def parse_headers(self):
        # headers list file does not contains lead and signature
        if not self.from_headers_list:
            # read lead
            rpm_lead = lead_struct.unpack(self.reader.read(lead_struct.size))
            if rpm_lead[0] != RPM_MAGIC:
                raise ValueError(f"File is not a RPM package")

            # set 'RPMTAG_SOURCEPACKAGE'
            if rpm_lead[3] != 0:
                self.hdr[rpmh[rpmh.RPMTAG_SOURCEPACKAGE]] = 1

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
            for _ in range(rpm_sig.nindex - 1):
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
        for _ in range(rpm_header.nindex - 1):
            rpm_tag = RPMTagS(*tag_struct.unpack(self.reader.read(tag_struct.size)))
            self.extract_tag_content(rpm_tag, is_sig_tag=False)


class RPMHeadersList:
    def __init__(self):
        self.hdrs = []

    def _parse_hdrs_list(self, reader: Union[BinaryIO, Any]):
        while True:
            try:
                parser = RPMHeaderParser(reader, from_headers_list=True)
                self.hdrs.append(parser.hdr)
                reader.seek(parser.compressed_payload_offset)
            except (ValueError, StructError):
                break

    def parse_headers_list(self, hdr_list_file):
        with io.open(hdr_list_file, "rb") as f:
            self._parse_hdrs_list(f)
        return self.hdrs

    def parse_compressed_headers_list(self, xz_headers_file):
        with lzma.open(xz_headers_file, "rb") as f:
            self._parse_hdrs_list(f)
        return self.hdrs


_FileOrPath = Union[str, bytes, PathLike]


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
            self.payload_compressor = self.hdr["RPMTAG_PAYLOADCOMPRESSOR"]

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
                if entry.isfile and (entry.name.endswith(".spec") or entry.name == "spec"):
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
