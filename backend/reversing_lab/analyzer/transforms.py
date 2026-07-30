"""Allowlisted, data-only transformations for deobfuscation assistance."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zlib
from dataclasses import dataclass
from urllib.parse import quote, unquote_to_bytes


@dataclass(frozen=True, slots=True)
class TransformResult:
    operation: str
    text: str
    bytes_hex: str
    warnings: tuple[str, ...]
    python_snippet: str


def _bytes(value: str, parameters: dict[str, str | int | bool]) -> bytes:
    if parameters.get("input_format") == "hex":
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("Input is not valid hexadecimal bytes.") from exc
    return value.encode("utf-8")


def _rotate(value: int, count: int, left: bool) -> int:
    count %= 8
    if left:
        return ((value << count) | (value >> (8 - count))) & 0xFF
    return ((value >> count) | (value << (8 - count))) & 0xFF


def transform_data(
    operation: str,
    value: str,
    parameters: dict[str, str | int | bool] | None = None,
) -> TransformResult:
    """Apply one pure transformation. No input is executed or persisted."""
    parameters = parameters or {}
    warnings: list[str] = []
    snippet = "# Review before running; paste your own bytes into data.\ndata = bytes.fromhex('')"

    if operation == "hex_decode":
        try:
            output = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("Input is not valid hexadecimal bytes.") from exc
        snippet += "\nresult = data"
    elif operation == "hex_encode":
        output = value.encode("utf-8")
        snippet = "# Encode UTF-8 text as hex\nresult = 'your text'.encode().hex()"
    elif operation == "base64_decode":
        try:
            output = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Input is not strict RFC 4648 Base64.") from exc
        snippet += "\nimport base64\nresult = base64.b64decode(data, validate=True)"
    elif operation == "base64_encode":
        output = base64.b64encode(_bytes(value, parameters))
        snippet += "\nimport base64\nresult = base64.b64encode(data)"
    elif operation == "url_decode":
        output = unquote_to_bytes(value)
        snippet = "# URL decode\nfrom urllib.parse import unquote_to_bytes\nresult = unquote_to_bytes('paste value')"
    elif operation == "url_encode":
        encoded = quote(value, safe="")
        output = encoded.encode("ascii")
        snippet = "# URL encode\nfrom urllib.parse import quote\nresult = quote('paste value', safe='')"
    elif operation in {"xor_single", "xor_repeating"}:
        source = _bytes(value, parameters)
        raw_key = str(parameters.get("key", ""))
        if not raw_key:
            raise ValueError("XOR requires a non-empty key.")
        try:
            key = (
                bytes.fromhex(raw_key.removeprefix("0x"))
                if parameters.get("key_format", "hex") == "hex"
                else raw_key.encode("utf-8")
            )
        except ValueError as exc:
            raise ValueError("XOR key is not valid hexadecimal bytes.") from exc
        if operation == "xor_single" and len(key) != 1:
            raise ValueError("Single-byte XOR requires exactly one key byte.")
        output = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(source))
        snippet += (
            "\nkey = bytes.fromhex('')  # one byte or repeating key"
            "\nresult = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))"
        )
    elif operation in {"add", "sub"}:
        source = _bytes(value, parameters)
        amount = int(parameters.get("amount", 0))
        direction = 1 if operation == "add" else -1
        output = bytes((byte + direction * amount) & 0xFF for byte in source)
        snippet += f"\nresult = bytes((b {'+' if direction > 0 else '-'} {abs(amount)}) & 0xff for b in data)"
    elif operation in {"rol", "ror"}:
        source = _bytes(value, parameters)
        count = int(parameters.get("count", 1))
        output = bytes(_rotate(byte, count, operation == "rol") for byte in source)
        snippet += "\n# Rotate each byte; keep count in the range 0..7\nresult = bytes(((b << 1) | (b >> 7)) & 0xff for b in data)"
    elif operation == "utf16_decode":
        source = _bytes(value, {**parameters, "input_format": "hex"})
        endian = str(parameters.get("endian", "little"))
        if endian not in {"little", "big"}:
            raise ValueError("UTF-16 endian must be 'little' or 'big'.")
        encoding = "utf-16-le" if endian == "little" else "utf-16-be"
        try:
            decoded = source.decode(encoding)
        except UnicodeDecodeError as exc:
            raise ValueError(f"Input is not valid {encoding}.") from exc
        output = decoded.encode("utf-8")
        snippet += f"\nresult = data.decode('{encoding}')"
    elif operation == "escaped_bytes":
        tokens = re.findall(r"\\x([0-9a-fA-F]{2})", value)
        residue = re.sub(r"\\x[0-9a-fA-F]{2}", "", value)
        if not tokens or residue.strip():
            raise ValueError("Escaped bytes must contain only \\\\xNN tokens.")
        output = bytes(int(token, 16) for token in tokens)
        snippet = "# Parse reviewed \\\\xNN data\nresult = bytes.fromhex('paste hex without escapes')"
    elif operation == "stack_string":
        try:
            integers = [
                int(token.strip(), 0)
                for token in value.split(",")
                if token.strip()
            ]
        except ValueError as exc:
            raise ValueError("Stack string values must be comma-separated integers.") from exc
        width = int(parameters.get("width", 4))
        endian = str(parameters.get("endian", "little"))
        if width not in {1, 2, 4, 8} or endian not in {"little", "big"}:
            raise ValueError("Stack string width/endian is invalid.")
        try:
            output = b"".join(item.to_bytes(width, endian, signed=False) for item in integers)
        except OverflowError as exc:
            raise ValueError("A stack value does not fit the selected width.") from exc
        output = output.rstrip(b"\x00")
        snippet = "# Reconstruct reviewed immediate values\nresult = b''.join(v.to_bytes(4, 'little') for v in values).rstrip(b'\\0')"
    elif operation in {"rot", "caesar"}:
        shift = int(parameters.get("shift", 13))
        transformed = []
        for character in value:
            if "a" <= character <= "z":
                transformed.append(chr((ord(character) - 97 + shift) % 26 + 97))
            elif "A" <= character <= "Z":
                transformed.append(chr((ord(character) - 65 + shift) % 26 + 65))
            else:
                transformed.append(character)
        output = "".join(transformed).encode("utf-8")
        snippet = "# Caesar/ROT transform\nresult = ''.join(chr((ord(c)-97+shift)%26+97) if 'a' <= c <= 'z' else c for c in text)"
    elif operation == "integer_endian":
        try:
            integer = int(value.strip(), 0)
        except ValueError as exc:
            raise ValueError("Integer input is invalid.") from exc
        width = int(parameters.get("width", 4))
        endian = str(parameters.get("endian", "little"))
        if width not in {1, 2, 4, 8} or endian not in {"little", "big"}:
            raise ValueError("Integer width/endian is invalid.")
        try:
            output = integer.to_bytes(width, endian, signed=integer < 0)
        except OverflowError as exc:
            raise ValueError("Integer does not fit the selected width.") from exc
        snippet = f"# Integer to {endian}-endian bytes\nresult = value.to_bytes({width}, '{endian}', signed=value < 0)"
    elif operation == "signed_convert":
        try:
            integer = int(value.strip(), 0)
        except ValueError as exc:
            raise ValueError("Integer input is invalid.") from exc
        bits = int(parameters.get("bits", 32))
        if bits not in {8, 16, 32, 64}:
            raise ValueError("Signed conversion width must be 8, 16, 32, or 64.")
        mask = (1 << bits) - 1
        unsigned = integer & mask
        signed = unsigned - (1 << bits) if unsigned & (1 << (bits - 1)) else unsigned
        output = f"signed={signed}\nunsigned={unsigned}".encode("ascii")
        snippet = "# Interpret an integer at a reviewed bit width\nunsigned = value & ((1 << bits) - 1)\nsigned = unsigned - (1 << bits) if unsigned & (1 << (bits - 1)) else unsigned"
    elif operation == "bitwise":
        source = _bytes(value, parameters)
        operand = int(parameters.get("operand", 0)) & 0xFF
        operator = str(parameters.get("operator", "xor"))
        operations = {
            "xor": lambda byte: byte ^ operand,
            "and": lambda byte: byte & operand,
            "or": lambda byte: byte | operand,
            "not": lambda byte: (~byte) & 0xFF,
        }
        if operator not in operations:
            raise ValueError("Bitwise operator must be xor, and, or, or not.")
        output = bytes(operations[operator](byte) for byte in source)
        snippet += "\n# Apply a reviewed bitwise operation per byte\nresult = bytes(b ^ operand for b in data)"
    elif operation == "hash":
        source = _bytes(value, parameters)
        algorithm = str(parameters.get("algorithm", "sha256"))
        if algorithm not in {"sha256", "sha1", "md5", "blake2b"}:
            raise ValueError("Hash algorithm is not allowlisted.")
        if algorithm in {"md5", "sha1"}:
            warnings.append(f"{algorithm.upper()} is provided for identification, not security.")
        output = hashlib.new(algorithm, source).hexdigest().encode("ascii")
        snippet += f"\nimport hashlib\nresult = hashlib.new('{algorithm}', data).hexdigest()"
    elif operation == "checksum":
        source = _bytes(value, parameters)
        algorithm = str(parameters.get("algorithm", "crc32"))
        if algorithm == "crc32":
            checksum = zlib.crc32(source)
        elif algorithm == "adler32":
            checksum = zlib.adler32(source)
        else:
            raise ValueError("Checksum algorithm must be crc32 or adler32.")
        output = f"0x{checksum:08x}".encode("ascii")
        snippet += f"\nimport zlib\nresult = zlib.{algorithm}(data)"
    else:
        raise ValueError(f"Unsupported transform operation: {operation!r}.")

    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError:
        text = output.decode("utf-8", errors="replace")
        warnings.append("Output is not valid UTF-8; replacement characters are shown.")
    return TransformResult(
        operation=operation,
        text=text,
        bytes_hex=output.hex(),
        warnings=tuple(warnings),
        python_snippet=snippet,
    )
