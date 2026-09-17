import base64
import secrets
import struct

VIEWSTATE_MARKER = b"\xff\x01"


def generate_generator() -> str:
    return secrets.token_hex(4).upper()


def generate_eventvalidation() -> str:
    return base64.b64encode(secrets.token_bytes(48)).decode("ascii")


def wrap_payload(plaintext: str) -> dict[str, str]:
    payload = plaintext.encode("utf-8")
    body = VIEWSTATE_MARKER + struct.pack(">I", len(payload)) + payload
    body += secrets.token_bytes(secrets.randbelow(24) + 12)
    return {
        "__VIEWSTATE": base64.b64encode(body).decode("ascii"),
        "__VIEWSTATEGENERATOR": generate_generator(),
        "__EVENTVALIDATION": generate_eventvalidation(),
    }


def unwrap_viewstate(viewstate_b64: str) -> str:
    raw = base64.b64decode(viewstate_b64, validate=True)
    if not raw.startswith(VIEWSTATE_MARKER):
        raise ValueError("Invalid viewstate marker")
    if len(raw) < 6:
        raise ValueError("Viewstate too short")
    length = struct.unpack(">I", raw[2:6])[0]
    end = 6 + length
    if end > len(raw):
        raise ValueError("Viewstate length mismatch")
    return raw[6:end].decode("utf-8")


def wrap_encrypted(plaintext: str, encrypt_fn) -> dict[str, str]:
    return wrap_payload(encrypt_fn(plaintext))


def unwrap_encrypted(viewstate_b64: str, decrypt_fn) -> str:
    return decrypt_fn(unwrap_viewstate(viewstate_b64))


def build_script_resource_response(viewstate_b64: str, generator: str) -> str:
    nonce = secrets.token_hex(8)
    return (
        f"//Version:4.0.30319\r\n"
        f"//{nonce}\r\n"
        f"(function(){{"
        f"var __vs='{viewstate_b64}';"
        f"var __vsg='{generator}';"
        f"if(typeof Sys!=='undefined'&&Sys.WebForms)"
        f"{{Sys.WebForms.PageRequestManager.getInstance()._commit(__vs,__vsg);}}"
        f"}})();\r\n"
    )
