# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class RtlConfig(KaitaiStruct):
    """Config format used by Realtek to write values to memory/flash?
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = RtlConfig.MainHeader(self._io, self, self._root)
        self.entries = []
        i = 0
        while not self._io.is_eof():
            self.entries.append(RtlConfig.RtlTlv(self._io, self, self._root))
            i += 1


    class MainHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x55\xAB\x23\x87":
                raise kaitaistruct.ValidationNotEqualError(b"\x55\xAB\x23\x87", self.magic, self._io, u"/types/main_header/seq/0")
            self.total_size = self._io.read_u2le()


    class RtlTlv(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u2le()
            self.len_value = self._io.read_u1()
            self.value = self._io.read_bytes(self.len_value)



