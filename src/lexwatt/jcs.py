"""RFC 8785 (JCS) canonical JSON with the LexWatt integer-only numeric profile.

Wire rules (spec §4.1):
- UTF-8, no BOM, no duplicate keys, no lone surrogates, no trailing data.
- Object keys are emitted sorted by UTF-16 code units.
- JSON numbers are restricted to canonical integers: ``-?(0|[1-9][0-9]*)``
  with absolute value <= 2147483647.  No exponent, fraction, leading zero,
  or negative zero.  Larger quantities travel as ``U`` decimal strings.
- Frame depth is bounded (32) before acting on the document.
"""

from __future__ import annotations

from .errors import LexwattError

MAX_DEPTH = 32
MAX_JSON_INT = 2147483647


def _utf16_sort_key(s: str):
    return s.encode("utf-16-be", "surrogatepass")


def _escape_string(s: str, out: list[str]) -> None:
    out.append('"')
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise LexwattError("INVALID_INPUT")
        else:
            out.append(ch)
    out.append('"')


def _write(value, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, str):
        _escape_string(value, out)
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        keys = sorted(value.keys(), key=_utf16_sort_key)
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            if not isinstance(k, str):
                raise LexwattError("INVALID_INPUT")
            _escape_string(k, out)
            out.append(":")
            _write(value[k], out)
        out.append("}")
    else:
        raise LexwattError("INVALID_INPUT")


def dumps(value) -> bytes:
    """Serialize to canonical UTF-8 bytes."""
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")


def dumps_str(value) -> str:
    return dumps(value).decode("utf-8")


_HEX = "0123456789abcdef"


class _Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.n = len(data)

    def fail(self) -> LexwattError:
        return LexwattError("INVALID_INPUT")

    def peek(self) -> int:
        return self.data[self.pos] if self.pos < self.n else -1

    def take(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def ws(self) -> None:
        while self.pos < self.n and self.data[self.pos] in (0x20, 0x09, 0x0A, 0x0D):
            self.pos += 1

    def parse(self):
        self.ws()
        v = self.value(0)
        self.ws()
        if self.pos != self.n:
            raise self.fail()
        return v

    def value(self, depth: int):
        if depth > MAX_DEPTH:
            raise self.fail()
        b = self.peek()
        if b < 0:
            raise self.fail()
        if b == 0x7B:  # {
            return self.obj(depth)
        if b == 0x5B:  # [
            return self.arr(depth)
        if b == 0x22:  # "
            return self.string()
        if b == 0x74:  # t
            self.expect(b"true")
            return True
        if b == 0x66:
            self.expect(b"false")
            return False
        if b == 0x6E:
            self.expect(b"null")
            return None
        if b == 0x2D or 0x30 <= b <= 0x39:
            return self.number()
        raise self.fail()

    def expect(self, lit: bytes) -> None:
        if self.data[self.pos : self.pos + len(lit)] != lit:
            raise self.fail()
        self.pos += len(lit)

    def number(self) -> int:
        start = self.pos
        if self.peek() == 0x2D:
            self.pos += 1
        if self.peek() == 0x30:
            self.pos += 1
            # canonical integer grammar forbids any digit after a leading zero
            if 0x30 <= self.peek() <= 0x39:
                raise self.fail()
        elif 0x31 <= self.peek() <= 0x39:
            while 0x30 <= self.peek() <= 0x39:
                self.pos += 1
        else:
            raise self.fail()
        if self.peek() in (0x2E, 0x65, 0x45):  # . e E
            raise self.fail()
        text = self.data[start : self.pos].decode("ascii")
        v = int(text)
        if abs(v) > MAX_JSON_INT:
            raise self.fail()
        return v

    def string(self) -> str:
        assert self.take() == 0x22
        out: list[str] = []
        while True:
            if self.pos >= self.n:
                raise self.fail()
            b = self.take()
            if b == 0x22:
                break
            if b == 0x5C:  # backslash
                if self.pos >= self.n:
                    raise self.fail()
                e = self.take()
                if e == 0x22:
                    out.append('"')
                elif e == 0x5C:
                    out.append("\\")
                elif e == 0x2F:
                    out.append("/")
                elif e == 0x62:
                    out.append("\b")
                elif e == 0x66:
                    out.append("\f")
                elif e == 0x6E:
                    out.append("\n")
                elif e == 0x72:
                    out.append("\r")
                elif e == 0x74:
                    out.append("\t")
                elif e == 0x75:
                    out.append(self.u_escape())
                else:
                    raise self.fail()
            elif b < 0x20:
                raise self.fail()
            elif b < 0x80:
                out.append(chr(b))
            else:
                out.append(self.utf8_char(b))
        s = "".join(out)
        self.check_scalars(s)
        return s

    def u_escape(self) -> str:
        if self.pos + 4 > self.n:
            raise self.fail()
        hexs = self.data[self.pos : self.pos + 4]
        self.pos += 4
        try:
            cp = int(hexs.decode("ascii"), 16)
        except ValueError:
            raise self.fail()
        if 0xD800 <= cp <= 0xDBFF:
            # high surrogate must be followed by \uXXXX low surrogate
            if self.data[self.pos : self.pos + 2] != b"\\u":
                raise self.fail()
            self.pos += 2
            if self.pos + 4 > self.n:
                raise self.fail()
            hexs2 = self.data[self.pos : self.pos + 4]
            self.pos += 4
            try:
                cp2 = int(hexs2.decode("ascii"), 16)
            except ValueError:
                raise self.fail()
            if not (0xDC00 <= cp2 <= 0xDFFF):
                raise self.fail()
            cp = 0x10000 + ((cp - 0xD800) << 10) + (cp2 - 0xDC00)
        return chr(cp)

    def utf8_char(self, first: int) -> str:
        # input was already validated as UTF-8 at the byte level by loads();
        # decode a multi-byte sequence here
        need = 0
        if 0xC0 <= first <= 0xDF:
            need = 1
        elif 0xE0 <= first <= 0xEF:
            need = 2
        elif 0xF0 <= first <= 0xF7:
            need = 3
        else:
            raise self.fail()
        seq = bytes([first]) + self.data[self.pos : self.pos + need]
        self.pos += need
        try:
            return seq.decode("utf-8")
        except UnicodeDecodeError:
            raise self.fail()

    @staticmethod
    def check_scalars(s: str) -> None:
        for ch in s:
            o = ord(ch)
            if 0xD800 <= o <= 0xDFFF:
                raise LexwattError("INVALID_INPUT")

    def obj(self, depth: int):
        self.pos += 1  # {
        out = {}
        self.ws()
        if self.peek() == 0x7D:
            self.pos += 1
            return out
        while True:
            self.ws()
            if self.peek() != 0x22:
                raise self.fail()
            k = self.string()
            self.ws()
            if self.take() != 0x3A:  # :
                raise self.fail()
            self.ws()
            v = self.value(depth + 1)
            if k in out:
                raise LexwattError("INVALID_INPUT")  # duplicate key
            out[k] = v
            self.ws()
            b = self.take()
            if b == 0x7D:
                return out
            if b != 0x2C:
                raise self.fail()

    def arr(self, depth: int):
        self.pos += 1  # [
        out = []
        self.ws()
        if self.peek() == 0x5D:
            self.pos += 1
            return out
        while True:
            self.ws()
            out.append(self.value(depth + 1))
            self.ws()
            b = self.take()
            if b == 0x5D:
                return out
            if b != 0x2C:
                raise self.fail()


def loads(data: bytes):
    """Strict decode of canonical JSON bytes under the LexWatt profile."""
    if not isinstance(data, (bytes, bytearray)):
        raise LexwattError("INVALID_INPUT")
    raw = bytes(data)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise LexwattError("INVALID_INPUT")
    try:
        raw.decode("utf-8")  # rejects invalid UTF-8 and lone surrogates
    except UnicodeDecodeError:
        raise LexwattError("INVALID_INPUT")
    return _Parser(raw).parse()


def loads_str(text: str):
    if not isinstance(text, str):
        raise LexwattError("INVALID_INPUT")
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        raise LexwattError("INVALID_INPUT")
    return loads(data)
