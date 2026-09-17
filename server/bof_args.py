import struct


def pack_string_args(args: list[str]) -> bytes:
    """Pack BOF args as null-terminated UTF-8 strings (CS z-style sequence)."""
    packed = bytearray()
    for arg in args:
        packed.extend(arg.encode("utf-8"))
        packed.append(0)
    return bytes(packed)


def pack_typed_args(spec: str, values: list[str]) -> bytes:
    """
    Pack args using a simple CS-like format string.
    Supported: z (cstring), i (int32), s (int16).
    """
    if len(spec) != len(values):
        raise ValueError("format string length must match number of arguments")
    packed = bytearray()
    for kind, value in zip(spec, values):
        if kind == "z":
            packed.extend(value.encode("utf-8"))
            packed.append(0)
        elif kind == "i":
            packed.extend(struct.pack("<i", int(value)))
        elif kind == "s":
            packed.extend(struct.pack("<h", int(value)))
        else:
            raise ValueError(f"unsupported BOF arg type: {kind}")
    return bytes(packed)
