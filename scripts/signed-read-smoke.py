#!/usr/bin/env python3
"""Exercise signed reads across disposable Control Tower and node processes.

Build both binaries first and pass their paths with --node-bin and --control-bin.
Requires OpenSSL with Ed25519 support. No existing state is modified.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def freeport():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(base, method, path, body=None, cookie=None, token=None, headers=None):
    headers = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as response:
        return response.code, response.read(), response.headers


def expect(response, status):
    if response[0] != status:
        raise RuntimeError(f"expected {status}, got {response[0]}: {response[1][:500]}")
    return response


def wait_ready(base, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"process exited {process.returncode}")
        try:
            if request(base, "GET", "/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("health timeout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-bin", required=True)
    parser.add_argument("--control-bin", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="jolt-signed-smoke-") as temp:
        root = Path(temp)
        (root / "files").mkdir()
        (root / "files" / "hello.txt").write_text("signed read ok")
        (root / "files" / "hide.pem").write_text("fictional")
        private = root / "private.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        public = subprocess.check_output(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"]
        )[-32:]
        encoded_public = base64.b64encode(public).decode()
        node_port, mtls_port, control_port = freeport(), freeport(), freeport()
        node_base = f"http://127.0.0.1:{node_port}"
        control_base = f"http://127.0.0.1:{control_port}"
        node_token, password = secrets.token_hex(32), secrets.token_hex(24)
        cfg = root / "node.yaml"
        cfg.write_text(f'''version: 1
node_name: signed-smoke
api_address: "127.0.0.1:{node_port}"
mtls_address: "127.0.0.1:{mtls_port}"
mtls_public_endpoint: "https://127.0.0.1:{mtls_port}"
data_dir: {json.dumps(str(root / "state"))}
keys_dir: {json.dumps(str(root / "keys"))}
authorization_public_keys:
  - id: smoke
    key: "{encoded_public}"
mounts:
  - id: files
    name: Files
    local_path: {json.dumps(str(root / "files"))}
    mode: read_write
    published: true
    enabled: true
    hidden_patterns: ["*.pem"]
transfer_grants: []
''')
        common = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("CONTROL_TOWER_", "JOLT_"))
        }
        nenv = dict(
            common, CONTROL_TOWER_TOKEN=node_token,
            JOLT_STATE_ENCRYPTION_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),
        )
        cenv = dict(
            common, CONTROL_TOWER_ADDRESS=f"127.0.0.1:{control_port}",
            CONTROL_TOWER_DATA_DIR=str(root / "control"),
            CONTROL_TOWER_STATIC_DIR=str(root / "static"),
            CONTROL_TOWER_ADMIN_PASSWORD=password,
            CONTROL_TOWER_DB_ENCRYPTION_KEY=secrets.token_hex(32),
            CONTROL_TOWER_SECURE_COOKIES="false",
            CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_FILE=str(private),
            CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_ID="smoke",
            CONTROL_TOWER_SIGNED_LOCAL_READS="true",
        )
        node_log = (root / "node.log").open("w+")
        control_log = (root / "control.log").open("w+")
        processes = []

        def start_node():
            process = subprocess.Popen(
                [args.node_bin, "--config", str(cfg)], env=nenv,
                stdout=node_log, stderr=node_log,
            )
            processes.append(process)
            wait_ready(node_base, process)
            return process

        try:
            node = start_node()
            control = subprocess.Popen(
                [args.control_bin], env=cenv, stdout=control_log, stderr=control_log,
            )
            processes.append(control)
            wait_ready(control_base, control)
            meta = json.loads(expect(request(node_base, "GET", "/api/v1/node", token=node_token), 200)[1])
            assert "signed_local_read_v1" in meta["capabilities"]
            assert "signed_local_tree_read_v1" in meta["capabilities"]
            login = expect(request(
                control_base, "POST", "/api/v1/control-tower/auth/login",
                {"username": "admin", "password": password},
            ), 200)
            cookie = login[2]["Set-Cookie"].split(";", 1)[0]
            registration = expect(request(
                control_base, "POST", "/api/v1/control-tower/nodes",
                {"name": "smoke", "endpoint": node_base, "token": node_token}, cookie=cookie,
            ), 201)
            node_id = json.loads(registration[1])["node_id"]
            prefix = f"/api/v1/nodes/{node_id}/mounts/files/files"
            listing = expect(request(control_base, "GET", prefix, cookie=cookie), 200)[1]
            assert b"hello.txt" in listing and b"hide.pem" not in listing
            content = expect(request(
                control_base, "GET", prefix + "/content?path=hello.txt", cookie=cookie,
                headers={"Range": "bytes=0-5"},
            ), 206)
            assert content[1] == b"signed"
            expect(request(control_base, "GET", prefix + "/metadata?path=hello.txt", cookie=cookie), 200)
            expect(request(control_base, "GET", prefix + "/content?path=hide.pem", cookie=cookie), 404)
            for path in ("/search?query=hello", "/disk-usage", "/archive/plan", "/archive"):
                response = expect(request(control_base, "GET", prefix + path, cookie=cookie), 200)
                assert b"hide.pem" not in response[1]
            print("PASS: signed proxy and node: list, hidden name, range, metadata, search, disk usage and ZIP")

            node.terminate()
            node.wait(timeout=10)
            original = cfg.read_text()
            wrong_key = base64.b64encode(secrets.token_bytes(32)).decode()
            cfg.write_text(original.replace(encoded_public, wrong_key))
            node = start_node()
            expect(request(control_base, "GET", prefix + "/content?path=hello.txt", cookie=cookie), 409)

            node.terminate()
            node.wait(timeout=10)
            config_text = cfg.read_text()
            config_text = config_text[:config_text.index("authorization_public_keys:")] + config_text[config_text.index("mounts:"):]
            cfg.write_text(config_text)
            start_node()
            expect(request(control_base, "GET", prefix + "/content?path=hello.txt", cookie=cookie), 409)
            print("PASS: mismatched key and missing node capability fail closed")
        except Exception:
            for label, log in (("node", node_log), ("control", control_log)):
                log.flush()
                log.seek(0)
                output = log.read().replace(node_token, "[redacted]").replace(password, "[redacted]")
                print(label + " log:", output[-3000:])
            raise
        finally:
            for process in reversed(processes):
                process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            node_log.close()
            control_log.close()


if __name__ == "__main__":
    main()
