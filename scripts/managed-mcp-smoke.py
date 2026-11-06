#!/usr/bin/env python3
"""Trust a real Control Tower's root from jolt-mcp, and keep trusting it through a root rotation.

Build jolt-control and jolt-mcp first and pass their paths with --control-bin
and --mcp-bin. No existing state is modified: everything lives in a temporary
directory, on loopback, on free ports, with a throwaway HOME for jolt-mcp.

It checks what only real processes can show: jolt-mcp refusing a Control
Tower under a root it was never given, `trust` refusing a wrong fingerprint,
`trust` taking the root from the plain-HTTP page and from the HTTPS listener,
the MCP server then reaching the Control Tower over TLS with no configuration,
and a root rotation: an agent that took the next root keeps working after the
promotion, one that did not is cut off.
"""

import argparse
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True  # importing the sibling script must leave nothing in the repository
import importlib.util

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("managed_tls_smoke", here / "managed-tls-smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

CT = "/api/v1/control-tower/"


def mcp_call(binary, home, control_url, credential, extra_env=None):
    """Start jolt-mcp, call `list` once over STDIO, and return (is_error, text)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("JOLT_")}
    env.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"), "JOLT_MCP_CONTROL_URL": control_url,
                "JOLT_MCP_CREDENTIAL_FILE": str(credential)})
    env.update(extra_env or {})
    process = subprocess.Popen([binary], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list", "arguments": {"node_id": "n", "mount_id": "m", "path": ""}}},
    ]
    timer = threading.Timer(60, process.kill)
    timer.start()
    try:
        # The server stops at the end of its input, so keep it open until the answer is in.
        for message in messages:
            process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        replies = {}
        for line in process.stdout:
            if line.strip():
                reply = json.loads(line)
                if "id" in reply:
                    replies[reply["id"]] = reply
                if 2 in replies:
                    break
        if 2 not in replies:
            raise RuntimeError("jolt-mcp stopped without answering: " + process.stderr.read())
    finally:
        timer.cancel()
        process.stdin.close()
        process.kill()
        process.wait()
    result = replies[2]
    if "error" in result:
        return True, result["error"]["message"]
    text = "".join(part.get("text", "") for part in result["result"]["content"])
    return bool(result["result"].get("isError")), text


def trust(binary, home, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("JOLT_")}
    env.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")})
    process = subprocess.run([binary, "trust", *args], env=env, capture_output=True, text=True, timeout=60)
    return process.returncode, process.stdout + process.stderr


def default_store(home):
    # macOS keeps it under Library, Linux under XDG_CONFIG_HOME.
    for candidate in (home / "Library" / "Application Support" / "jolt-mcp" / "ca.pem", home / "config" / "jolt-mcp" / "ca.pem"):
        if candidate.exists():
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-bin", required=True)
    parser.add_argument("--mcp-bin", required=True)
    args = parser.parse_args()
    processes = []
    try:
        with tempfile.TemporaryDirectory(prefix="jolt-mcp-smoke-") as temp:
            run(Path(temp), args, processes)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


def run(root, args, processes):
    port, ca_port = smoke.freeport(), smoke.freeport()
    control_url, public_url = f"https://127.0.0.1:{port}", f"http://127.0.0.1:{ca_port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CONTROL_TOWER_", "JOLT_"))}
    env.update({
        "CONTROL_TOWER_TLS_MODE": "managed", "CONTROL_TOWER_ADDRESS": f"127.0.0.1:{port}", "CONTROL_TOWER_CA_ADDRESS": f"127.0.0.1:{ca_port}",
        "CONTROL_TOWER_PUBLIC_BASE_URL": control_url, "CONTROL_TOWER_DATA_DIR": str(root / "control"),
        "CONTROL_TOWER_ADMIN_PASSWORD": "smoke-admin-password", "CONTROL_TOWER_DB_ENCRYPTION_KEY": "smoke-encryption-key-that-is-long-enough-1234",
        "CONTROL_TOWER_STATIC_DIR": str(root),
    })
    smoke.start([args.control_bin], env, root / "control.log", processes)
    insecure = smoke.Client(control_url)
    insecure.context = ssl._create_unverified_context()
    smoke.wait(lambda: insecure.call("GET", "/health")[0] == 200, "the Control Tower to start")
    status, root_pem, _ = insecure.call("GET", "/.well-known/jolt/ca.pem")
    assert status == 200
    (root / "root.pem").write_bytes(root_pem)
    control = smoke.Client(control_url, cafile=str(root / "root.pem"))
    status, _, headers = control.call("POST", CT + "auth/login", {"username": "admin", "password": "smoke-admin-password"})
    assert status == 200, status
    control.cookie = headers["Set-Cookie"].split(";")[0]
    # The fingerprint an operator copies from another channel: the authenticated API.
    fingerprint = control.json("GET", CT + "crypto/ca")["root_fingerprint"]
    credential = root / "credential"
    credential.write_text("smoke-agent-token\n")
    credential.chmod(0o600)
    reached = re.compile(r"Control Tower returned HTTP (4\d\d)")

    # 1. A Control Tower under a root the agent never got.
    home = root / "agent"
    home.mkdir()
    is_error, text = mcp_call(args.mcp_bin, home, control_url, credential)
    assert is_error and "request failed" in text, (is_error, text)
    print("ok   jolt-mcp does not reach a Control Tower whose root it was never given")

    # 2. A wrong fingerprint stores nothing.
    code, output = trust(args.mcp_bin, home, public_url, "--fingerprint", "00" * 32)
    assert code == 1 and "not the one given" in output, (code, output)
    assert default_store(home) is None, "a root was stored under a wrong fingerprint"
    print("ok   trust refuses a root whose fingerprint differs and stores nothing")

    # 3. The right one, from the plain-HTTP page, in the form the console prints.
    shown = ":".join(fingerprint[i:i + 2] for i in range(0, 64, 2)).upper()
    code, output = trust(args.mcp_bin, home, public_url, "--fingerprint", shown)
    assert code == 0 and fingerprint in output, (code, output)
    store = default_store(home)
    assert store is not None and oct(store.stat().st_mode & 0o777) == "0o600", store
    is_error, text = mcp_call(args.mcp_bin, home, control_url, credential)
    assert is_error and reached.search(text), (is_error, text)
    print("ok   trust took the root from the plain-HTTP page, and the MCP server then reached the Control Tower over TLS with no configuration")

    # 4. The same from the HTTPS listener, which the agent cannot verify yet.
    other = root / "agent-https"
    other.mkdir()
    code, output = trust(args.mcp_bin, other, control_url, "--fingerprint", fingerprint)
    assert code == 0, (code, output)
    is_error, text = mcp_call(args.mcp_bin, other, control_url, credential)
    assert is_error and reached.search(text), (is_error, text)
    print("ok   trust also works against the HTTPS listener, authenticated by the fingerprint alone")

    # 5. A root rotation. One agent takes the next root in time; one does not.
    control.json("POST", CT + "crypto/ca/root/rotate", expect=202)
    next_fingerprint = control.json("GET", CT + "crypto/ca")["rotation"]["next_root_fingerprint"]
    assert next_fingerprint and next_fingerprint != fingerprint
    code, output = trust(args.mcp_bin, home, public_url, "--fingerprint", fingerprint, "--next")
    assert code == 1, "the current fingerprint was accepted for the next root"
    code, output = trust(args.mcp_bin, home, public_url, "--fingerprint", next_fingerprint, "--next")
    assert code == 0 and "(2 roots)" in output, (code, output)
    control.json("POST", CT + "crypto/ca/root/promote", {})
    print("ok   the next root was taken before the promotion, beside the current one")

    # The Control Tower now serves under the new root.
    is_error, text = mcp_call(args.mcp_bin, home, control_url, credential)
    assert is_error and reached.search(text), ("the agent that took the next root was cut off", text)
    is_error, text = mcp_call(args.mcp_bin, other, control_url, credential)
    assert is_error and "request failed" in text, ("the agent that did not was not cut off", text)
    print("ok   after the promotion the agent that took the next root keeps working, and the one that did not is cut off")

    # 6. Catching up afterwards is the same command, now against the current root.
    code, output = trust(args.mcp_bin, other, public_url, "--fingerprint", next_fingerprint)
    assert code == 0, (code, output)
    is_error, text = mcp_call(args.mcp_bin, other, control_url, credential)
    assert is_error and reached.search(text), (is_error, text)
    print("ok   the late agent catches up with one trust command")

    # 7. An explicit file that does not exist fails instead of falling back.
    is_error, text = mcp_call(args.mcp_bin, other, control_url, credential, {"JOLT_MCP_CA_FILE": str(root / "missing.pem")})
    assert is_error and "jolt-mcp trust" in text, (is_error, text)
    print("ok   an explicit CA file that is missing fails with the command that fixes it")
    print("done")


if __name__ == "__main__":
    main()
