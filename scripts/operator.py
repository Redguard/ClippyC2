#!/usr/bin/env python3
"""Interactive ClippyC2 operator console."""

from __future__ import annotations

import argparse
import atexit
import json
import mimetypes
import os
import secrets
import shlex
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

try:
    import readline
except ImportError:
    readline = None  # type: ignore[assignment]

HISTORY_FILE = os.path.expanduser("~/.clippyc2_history")
PROMPT = "clippyc2 > "
BUILTIN_COMMANDS = ("help", "status", "exec", "bof", "tasks", "exit", "quit")


class OperatorClient:
    def __init__(
        self,
        base_url: str,
        password: str,
        insecure: bool = False,
        ca_cert: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.password = password
        if ca_cert:
            self.ssl_context = ssl.create_default_context(cafile=ca_cert)
        else:
            self.ssl_context = ssl.create_default_context()
        if insecure:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def request_json(self, path: str, params: dict | None = None) -> dict:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        url = f"{self.base_url}{path}{query}"
        req = urllib.request.Request(url, headers={"X-Auth": self.password})
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise RuntimeError("authentication failed (check CLIPPYC2_OPERATOR_PASSWORD)") from exc
            try:
                return json.loads(exc.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError(f"request failed: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not reach server: {exc.reason}") from exc

    def exec_command(self, command: str) -> dict:
        return self.request_json("/server", {"cmd": command})

    def tasks(self, command_id: str | None = None) -> dict:
        params = {"id": command_id} if command_id else None
        return self.request_json("/tasks", params)

    def status(self) -> dict:
        return self.request_json("/status")

    def _post_multipart(self, path: str, fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> dict:
        boundary = secrets.token_hex(16)
        body = bytearray()
        for name, value in fields.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            body.extend(value.encode())
            body.extend(b"\r\n")
        for name, (filename, content, mime_type) in files.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            )
            body.extend(f"Content-Type: {mime_type}\r\n\r\n".encode())
            body.extend(content)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())

        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url,
            data=bytes(body),
            headers={
                "X-Auth": self.password,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise RuntimeError("authentication failed (check CLIPPYC2_OPERATOR_PASSWORD)") from exc
            try:
                return json.loads(exc.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError(f"request failed: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not reach server: {exc.reason}") from exc

    def queue_bof(self, file_path: str, args: list[str]) -> dict:
        with open(file_path, "rb") as handle:
            content = handle.read()
        filename = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        fields: dict[str, str] = {}
        if args:
            fields["args"] = "\0".join(args)
        return self._post_multipart(
            "/bof",
            fields,
            {"file": (filename, content, mime_type)},
        )


class LineCompleter:
    def __init__(self, client: OperatorClient) -> None:
        self.client = client
        self._matches: list[str] = []
        self._task_ids: list[str] | None = None

    def invalidate_tasks_cache(self) -> None:
        self._task_ids = None

    def _get_task_ids(self) -> list[str]:
        if self._task_ids is None:
            try:
                payload = self.client.tasks()
                self._task_ids = [row["id"] for row in payload.get("commands", [])]
            except RuntimeError:
                self._task_ids = []
        return self._task_ids

    def _task_id_completions(self, prefix: str) -> list[str]:
        matches: list[str] = []
        seen: set[str] = set()
        for command_id in self._get_task_ids():
            if command_id.startswith(prefix):
                if command_id not in seen:
                    seen.add(command_id)
                    matches.append(command_id)
            short_id = command_id[:8]
            if short_id.startswith(prefix) and short_id not in seen:
                seen.add(short_id)
                matches.append(short_id)
        return sorted(matches)

    def _exec_history_matches(self, prefix: str) -> list[str]:
        if readline is None:
            return []
        matches: set[str] = set()
        for index in range(1, readline.get_history_length() + 1):
            entry = readline.get_history_item(index)
            if not entry or not entry.startswith("exec "):
                continue
            command = entry[5:]
            if command.startswith(prefix):
                matches.add(command)
        return sorted(matches)

    def _bof_file_matches(self, prefix: str) -> list[str]:
        matches: set[str] = set()
        for directory in (os.getcwd(), os.path.join(os.getcwd(), "bofs")):
            if not os.path.isdir(directory):
                continue
            for entry in os.listdir(directory):
                if not entry.endswith((".o", ".obj")):
                    continue
                candidate = entry if not prefix else entry
                full_path = os.path.join(directory, entry)
                rel_path = os.path.relpath(full_path, os.getcwd())
                if rel_path.startswith(prefix) or entry.startswith(prefix):
                    matches.add(rel_path)
        return sorted(matches)

    def _build_matches(self, text: str) -> list[str]:
        line = readline.get_line_buffer()
        endidx = readline.get_endidx()
        before = line[:endidx]
        tokens = before.split()
        completing_new_word = len(before) == 0 or before.endswith((" ", "\t"))

        if not tokens or (len(tokens) == 1 and not completing_new_word):
            return [f"{cmd} " for cmd in BUILTIN_COMMANDS if cmd.startswith(text)]

        command = tokens[0].lower()
        if command == "tasks" and (len(tokens) > 1 or completing_new_word):
            return self._task_id_completions(text)
        if command == "bof" and (len(tokens) > 1 or completing_new_word):
            return self._bof_file_matches(text)
        if command == "exec" and (len(tokens) > 1 or completing_new_word):
            return self._exec_history_matches(text)

        return []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            self._matches = self._build_matches(text)
        try:
            return self._matches[state]
        except IndexError:
            return None


def setup_readline(client: OperatorClient) -> LineCompleter | None:
    if readline is None:
        return None

    completer = LineCompleter(client)
    if hasattr(readline, "set_history_length"):
        readline.set_history_length(2000)
    readline.set_completer(completer.complete)
    readline.set_completer_delims(" \t\n")
    if sys.platform == "darwin":
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

    try:
        readline.read_history_file(HISTORY_FILE)
    except FileNotFoundError:
        pass

    def _save_history() -> None:
        readline.write_history_file(HISTORY_FILE)

    atexit.register(_save_history)
    return completer


def add_history(line: str) -> None:
    if readline is None or not line.strip():
        return
    if readline.get_history_length():
        last = readline.get_history_item(readline.get_history_length())
        if last == line:
            return
    readline.add_history(line)


def fmt_time(ts: float | None) -> str:
    if ts is None:
        return "never"
    when = datetime.fromtimestamp(ts)
    age = int(time.time() - ts)
    if age < 60:
        ago = f"{age}s ago"
    elif age < 3600:
        ago = f"{age // 60}m ago"
    else:
        ago = f"{age // 3600}h ago"
    return f"{when.strftime('%Y-%m-%d %H:%M:%S')} ({ago})"


def print_banner(base_url: str) -> None:
    print()
    print("  ClippyC2 Operator Console")
    print(f"  Server: {base_url}")
    print("  Type 'help' for commands, 'exit' to quit")
    if readline is None:
        print("  Note: install readline support for history and tab completion")
    print()


def format_queue_item(item: dict | str, marker: str) -> str:
    if isinstance(item, dict):
        command = item.get("command") or ""
        command_id = item.get("id") or ""
        short_id = command_id[:8] if command_id else "????????"
        return f"    {marker} {command} [{short_id}]"
    return f"    {marker} {item}"


def format_status(stats: dict, base_url: str = "") -> str:
    queued = stats.get("queued_commands") or []
    last_result_command = stats.get("last_result_command") or ""
    last_result_id = stats.get("last_result_id") or ""
    poll_at = stats.get("last_poll_at")
    checkin_at = stats.get("last_checkin_at")
    activity_at = max((t for t in (poll_at, checkin_at) if t is not None), default=None)

    lines = ["  ClippyC2 Status"]
    if base_url:
        lines.append(f"  Server: {base_url}")
    lines.append("  " + "─" * 40)
    if queued:
        lines.append(f"  Queue ({len(queued)})        :")
        for index, item in enumerate(queued):
            marker = ">" if index == 0 else " "
            lines.append(format_queue_item(item, marker))
    else:
        lines.append("  Queue            : (empty)")
    last_queued = stats.get("last_command") or "(none)"
    last_queued_id = stats.get("last_command_id") or ""
    if last_queued_id:
        last_queued = f"{last_queued} [{last_queued_id[:8]}]"
    last_executed = last_result_command or "(none)"
    if last_result_id:
        last_executed = f"{last_executed} [{last_result_id[:8]}]"
    lines.extend([
        f"  Last queued      : {last_queued}",
        f"  Last executed    : {last_executed}",
        f"  Queued at        : {fmt_time(stats.get('last_command_at'))}",
        f"  Last browser act.: {fmt_time(activity_at)}",
        f"  Poll interval    : {stats.get('poll_interval_sec', '?')}s",
    ])
    return "\n".join(lines)


def format_tasks_list(payload: dict) -> str:
    commands = payload.get("commands") or []
    if not commands:
        return "[*] No commands recorded"

    col_id = 10
    col_type = 6
    col_cmd = 30
    col_status = 8
    rule_len = col_id + col_type + col_cmd + col_status + 6

    lines = [
        f"  {'ID':<{col_id}}  {'Type':<{col_type}}  {'Command':<{col_cmd}}  {'Status':<{col_status}}",
        "  " + "─" * rule_len,
    ]
    for item in commands:
        command_id = item.get("id") or ""
        short_id = command_id[:8]
        command_type = item.get("type") or "shell"
        command = item.get("command") or ""
        if len(command) > col_cmd:
            command = command[: col_cmd - 3] + "..."
        status = "done" if item.get("has_result") else "pending"
        lines.append(
            f"  {short_id:<{col_id}}  {command_type:<{col_type}}  {command:<{col_cmd}}  {status:<{col_status}}"
        )
    return "\n".join(lines)


def format_task_detail(payload: dict) -> str:
    command_id = payload.get("id") or payload.get("command_id") or ""
    command = payload.get("command") or ""
    result = payload.get("result") or ""
    queued_at = payload.get("queued_at") or ""
    completed_at = payload.get("completed_at") or ""
    if not command_id and not command:
        return "[*] Command not found"
    lines: list[str] = []
    if command_id:
        lines.append(f"  ID: {command_id}")
    if command:
        lines.append(f"  Command: {command}")
    command_type = payload.get("type")
    if command_type:
        lines.append(f"  Type: {command_type}")
    if queued_at:
        lines.append(f"  Queued at: {queued_at}")
    if completed_at:
        lines.append(f"  Completed at: {completed_at}")
    if result:
        lines.append("  Result:")
        for line in result.rstrip().splitlines():
            lines.append(f"    {line}")
    elif payload.get("has_result") is False:
        lines.append("  Result: (pending)")
    else:
        lines.append("  Result: (none)")
    return "\n".join(lines)


def format_tasks(payload: dict) -> str:
    if payload.get("commands") is not None:
        return format_tasks_list(payload)
    return format_task_detail(payload)


def format_help() -> str:
    return "\n".join(
        [
            "Commands:",
            "  help                 Show this help",
            "  status               Show queue and browser activity",
            "  exec <command>       Queue a shell command for the agent",
            "  bof <file.o> [args]  Queue a Cobalt Strike BOF for agent_win",
            "  tasks                List all command IDs and status",
            "  tasks <id>           Show result for a command (id or prefix)",
            "  exit, quit           Leave the console",
        ]
    )


def run_command(
    client: OperatorClient,
    line: str,
    completer: LineCompleter | None,
) -> tuple[bool, str]:
    line = line.strip()
    if not line:
        return True, ""

    try:
        parts = shlex.split(line)
    except ValueError as exc:
        return True, f"[!] {exc}"

    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in {"exit", "quit"}:
        return False, ""
    if cmd == "help":
        return True, format_help()
    if cmd == "status":
        try:
            return True, format_status(client.status(), client.base_url)
        except RuntimeError as exc:
            return True, f"[!] {exc}"
    if cmd == "tasks":
        try:
            command_id = args[0] if args else None
            payload = client.tasks(command_id)
            if payload.get("status") == "error":
                message = payload.get("message") or "request failed"
                matches = payload.get("matches") or []
                if matches:
                    short_matches = ", ".join(match[:8] for match in matches)
                    return True, f"[!] {message}: {short_matches}"
                return True, f"[!] {message}"
            return True, format_tasks(payload)
        except RuntimeError as exc:
            return True, f"[!] {exc}"
    if cmd == "exec":
        if not args:
            return True, "[!] Usage: exec <command>"
        command = " ".join(args)
        try:
            response = client.exec_command(command)
            if completer:
                completer.invalidate_tasks_cache()
            sent = response.get("text_received", command)
            command_id = response.get("command_id") or ""
            queue_length = response.get("queue_length")
            if command_id and queue_length is not None:
                return True, f"[+] Queued: {sent} [{command_id[:8]}] ({queue_length} in queue)"
            if queue_length is not None:
                return True, f"[+] Queued: {sent} ({queue_length} in queue)"
            if command_id:
                return True, f"[+] Queued: {sent} [{command_id[:8]}]"
            return True, f"[+] Queued: {sent}"
        except RuntimeError as exc:
            return True, f"[!] {exc}"

    if cmd == "bof":
        if not args:
            return True, "[!] Usage: bof <file.o> [args...]"
        file_path = args[0]
        if not os.path.isfile(file_path):
            return True, f"[!] File not found: {file_path}"
        bof_args = args[1:]
        try:
            response = client.queue_bof(file_path, bof_args)
            if completer:
                completer.invalidate_tasks_cache()
            if response.get("status") == "error":
                return True, f"[!] {response.get('message', 'request failed')}"
            command_id = response.get("command_id") or ""
            name = response.get("name") or os.path.basename(file_path)
            queue_length = response.get("queue_length")
            if command_id and queue_length is not None:
                return True, f"[+] Queued BOF: {name} [{command_id[:8]}] ({queue_length} in queue)"
            if command_id:
                return True, f"[+] Queued BOF: {name} [{command_id[:8]}]"
            return True, f"[+] Queued BOF: {name}"
        except RuntimeError as exc:
            return True, f"[!] {exc}"

    return True, f"[!] Unknown command: {cmd}. Type 'help' for available commands."


def run_interactive(client: OperatorClient) -> None:
    print_banner(client.base_url)
    try:
        client.status()
        print("[+] Connected")
    except RuntimeError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    completer = setup_readline(client)

    while True:
        try:
            line = input(PROMPT)
        except (EOFError, KeyboardInterrupt):
            print()
            break

        add_history(line)
        keep_running, output = run_command(client, line, completer)
        if output:
            print()
            print(output)
            print()
        if not keep_running:
            break

    print("[*] Goodbye")


def run_oneshot(client: OperatorClient, command: str, args: list[str]) -> None:
    if command == "exec":
        if not args:
            sys.exit("Usage: operator.py <url> exec <command>")
        print(json.dumps(client.exec_command(" ".join(args)), indent=2))
    elif command == "tasks":
        command_id = args[0] if args else None
        print(json.dumps(client.tasks(command_id), indent=2))
    elif command == "status":
        print(json.dumps(client.status(), indent=2))
    else:
        sys.exit(f"Unknown command: {command}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ClippyC2 operator console")
    parser.add_argument("base_url", nargs="?", help="Server base URL, e.g. https://localhost:5000")
    parser.add_argument("--password", default=os.environ.get("CLIPPYC2_OPERATOR_PASSWORD", ""))
    parser.add_argument("command", nargs="?", help="Optional one-shot command: exec, tasks, status")
    parser.add_argument("cmd_args", nargs="*", help="Arguments for one-shot command")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        default=os.environ.get("CLIPPYC2_INSECURE") == "1",
        help="Disable TLS certificate verification (for self-signed certs in labs)",
    )
    parser.add_argument(
        "--cacert",
        default=os.environ.get("CLIPPYC2_CA_CERT"),
        help="Path to CA bundle file for TLS verification",
    )
    args = parser.parse_args()

    if not args.password:
        sys.exit("Set CLIPPYC2_OPERATOR_PASSWORD or pass --password")

    if not args.base_url:
        parser.print_help()
        sys.exit(1)

    client = OperatorClient(
        args.base_url,
        args.password,
        insecure=args.insecure,
        ca_cert=args.cacert,
    )

    if args.command:
        run_oneshot(client, args.command, args.cmd_args)
    else:
        run_interactive(client)


if __name__ == "__main__":
    main()
