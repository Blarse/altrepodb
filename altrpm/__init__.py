from .rpm import RPMHeaders, RPMHeaderList, RPMCpio

def readHeaderFromRPM(filename):
    rpm = RPMHeaders(filename)
    return rpm.hdrs

def readHeaderListFromFile(filename):
    rpm = RPMHeaderList(filename)
    return rpm.parse_hdr_list()

def readHeaderListFromXZFile(filename):
    # rpm = RPMHeaderList(filename)
    # return rpm.parse_hdr_list()
    raise NotImplementedError("support for read compressed headers list file not ipmlemented yet")

def extractSpecFromRPM(filename, raw):
    rpm = RPMCpio(filename)
    return rpm.get_spec(raw=raw)
