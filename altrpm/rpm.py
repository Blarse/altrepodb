import io
import bz2
import gzip
import lzma
import struct
from struct import error as StructError
import libarchive
import subprocess
from collections import namedtuple

from .rpmtag import rpmh, rpms, rpmt


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


def decompress_none(fileobj):
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


decompressors = {
    b"gzip": decompress_gzip,
    b"lzma": decompress_lzma,
    b"xz": decompress_lzma,
    b"zstd": decompress_zstd,
    b"bzip2": decompress_bzip2,
}


def bytes2integer(data, order="big"):
    return int.from_bytes(data, order)


def extract_bin(reader, base, offset, count, rewind=False):
    pos_ = reader.tell()
    reader.seek(base + offset)
    data = reader.read(count)
    if rewind:
        reader.seek(pos_)
    return data


def extract_char(reader, base, offset, count, rewind=False):
    count = 1
    return extract_bin(reader, base, offset, count, rewind)


def extract_int(reader, base, offset, count, width, rewind):
    pos_ = reader.tell()
    reader.seek(base + offset)
    data = reader.read(count * width)
    values = [bytes2integer(data[i * width : (i + 1) * width]) for i in range(count)]
    if rewind:
        reader.seek(pos_)
    return values


def extract_int8(reader, base, offset, count, rewind=False):
    return extract_int(reader, base, offset, count, 1, rewind)


def extract_int16(reader, base, offset, count, rewind=False):
    return extract_int(reader, base, offset, count, 2, rewind)


def extract_int32(reader, base, offset, count, rewind=False):
    return extract_int(reader, base, offset, count, 4, rewind)


def extract_int64(reader, base, offset, count, rewind=False):
    return extract_int(reader, base, offset, count, 8, rewind)


def extract_array(reader, base, offset, count, rewind=False):
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
    if count == 1:
        data = data[0]
    if rewind:
        reader.seek(pos_)
    return data


def extract_string(reader, base, offset, count, rewind=False):
    count = 1
    return extract_array(reader, base, offset, count, rewind)


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
    data = extract_string(fileobj, 0, 1, rewind=False)
    return data.decode(encoding)


class NoneDict(dict):
    def __getitem__(self, key):
        return dict.get(self, key)


class RPMHeaderParser:
    def __init__(self, reader, from_headers_list=False):
        self.from_headers_list = from_headers_list
        self.reader = reader
        self.hdr = NoneDict()
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


class RPMHeaderList:
    def __init__(self, rpm_file):
        self.hdrs = []
        self.rpm_file = rpm_file
        self.reader = io.open(self.rpm_file, "rb")

    def __del__(self):
        if self.reader:
            self.reader.close()

    def parse_hdr_list(self):
        while True:
            try:
                parser = RPMHeaderParser(self.reader, from_headers_list=True)
                self.hdrs.append(parser.hdr)
                self.reader.seek(parser.compressed_payload_offset)
            except (ValueError, StructError):
                break
        self.reader.close()
        return self.hdrs


class RPMHeaders:
    def __init__(self, rpm_file):
        self.hdrs = []
        self.rpm_file = rpm_file
        self.reader = io.open(self.rpm_file, "rb")

    def __del__(self):
        if self.reader:
            self.reader.close()

    def parse_headers(self):
        parser = RPMHeaderParser(self.reader)
        self.hdrs = parser.hdr
        self.reader.close
        return self.hdrs


class RPMCpio(RPMHeaderParser):
    def __init__(self, rpm_file):
        self.rpm_file = rpm_file
        self.reader = io.open(self.rpm_file, "rb")
        self.payload_compressor = None
        self.compressed_payload_offset = 0
        super().__init__(self.reader)

    def __del__(self):
        if self.reader:
            self.reader.close()

    def _extract_cpio(self):
        # # get payload compressor form tag #1125
        self.payload_compressor = self.hdr["RPMTAG_PAYLOADCOMPRESSOR"]
        # uncompressed cpio payload
        if self.payload_compressor is None:
            decompressor = decompress_none

        # if self.reader is None:
        #     self._open_rpm_file()

        self.reader.seek(self.compressed_payload_offset)

        decompressor = decompressors.get(self.payload_compressor, None)
        if decompressor is None:
            raise NotImplementedError(
                f"Decompressor not found for romat {self.payload_compressor}"
            )

        return decompressor(self.reader)

    def get_spec(self, raw=True):
        # read cpio content
        spec_file = b""
        with libarchive.memory_reader(self._extract_cpio()()) as archive:
            for entry in archive:
                if entry.isfile and entry.name.endswith(".spec"):
                    for block in entry.get_blocks():
                        spec_file += block
                    break

        if raw:
            return spec_file
        else:
            return spec_file.decode("utf-8", errors="backslashreplace")

    def extract(self):
        return self._extract_cpio()()


def readHeaderFromRPM(filename):
    rpm = RPMHeaders(filename)
    return rpm.hdrs

def readHeaderListFromFile(filename):
    rpm = RPMHeaderList(filename)
    return rpm.parse_hdr_list()

def readHeaderListFromXZFile(filename):
    # rpm = RPMHeaderList(filename)
    # return rpm.parse_hdr_list()
    return []

def extractSpecFromRPM(filename, raw):
    rpm = RPMCpio(filename)
    return rpm.get_spec(raw=raw)
