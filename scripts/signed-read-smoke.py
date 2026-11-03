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
            CONTROL_TOWER_SIGNED_UPLOADS="true",
        )
        node_log = (root / "node.log").open("w+")
        control_log = (root / "control.log").open("w+")
        processes = []
        automation_token = ""

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

            simple_path = prefix + "/content?path=simple.txt"
            simple_headers = {"Idempotency-Key": "simple-smoke"}
            expect(request(control_base, "PUT", simple_path, b"first", cookie=cookie, headers=simple_headers), 201)
            expect(request(control_base, "PUT", simple_path, b"second", cookie=cookie, headers=simple_headers), 200)
            assert (root / "files" / "simple.txt").read_bytes() == b"first"
            print("PASS: signed simple upload and idempotent retry")

            share = expect(request(
                control_base, "POST", "/api/v1/control-tower/shares",
                {"node_id": node_id, "mount_id": "files", "path": "hello.txt", "kind": "file", "max_downloads": 1}, cookie=cookie,
            ), 201)
            share_token = json.loads(share[1])["token"]
            public_path = "/api/v1/public/shares/" + share_token
            expect(request(control_base, "GET", public_path), 200)
            shared = expect(request(control_base, "GET", public_path + "/content", headers={"Range": "bytes=0-5"}), 206)
            assert shared[1] == b"signed"
            expect(request(control_base, "GET", public_path + "/content"), 410)
            directory = expect(request(
                control_base, "POST", "/api/v1/control-tower/shares",
                {"node_id": node_id, "mount_id": "files", "path": ".", "kind": "directory"}, cookie=cookie,
            ), 201)
            directory_path = "/api/v1/public/shares/" + json.loads(directory[1])["token"]
            listing = expect(request(control_base, "GET", directory_path + "/list"), 200)[1]
            archive = expect(request(control_base, "GET", directory_path + "/archive"), 200)[1]
            assert b"hello.txt" in listing and b"hide.pem" not in listing and b"hide.pem" not in archive
            print("PASS: signed public shares, range budget, listing and ZIP")

            group = expect(request(control_base, "POST", "/api/v1/control-tower/access-groups", {"name": "share-smoke"}, cookie=cookie), 201)
            group_id = json.loads(group[1])["group_id"]
            group_path = "/api/v1/control-tower/access-groups/" + group_id
            expect(request(control_base, "PUT", group_path + "/nodes", {"ids": [node_id]}, cookie=cookie), 200)
            policy = expect(request(control_base, "POST", "/api/v1/control-tower/policies", {
                "name": "share-smoke-policy", "rules": [
                    {"path": "control-tower/shares", "capabilities": ["create"]},
                    {"path": f"nodes/{node_id}/files/mounts/files/**", "capabilities": ["read", "list"]},
                ],
            }, cookie=cookie), 201)
            policy_id = json.loads(policy[1])["policy_id"]
            expect(request(control_base, "PUT", group_path + "/policies", {"ids": [policy_id]}, cookie=cookie), 200)
            account = expect(request(control_base, "POST", "/api/v1/control-tower/service-accounts", {
                "name": "share-smoke-automation", "kind": "automation", "group_ids": [group_id],
            }, cookie=cookie), 201)
            account_data = json.loads(account[1])
            automation = account_data["service_account"]["service_account_id"]
            credential = account_data["credential"]
            automation_token = credential["token"]
            automated_share = expect(request(control_base, "POST", "/api/v1/control-tower/shares", {
                "node_id": node_id, "mount_id": "files", "path": "hello.txt", "kind": "file",
            }, token=automation_token), 201)
            assert b"created_credential_id" not in automated_share[1]
            automated_path = "/api/v1/public/shares/" + json.loads(automated_share[1])["token"]
            expect(request(control_base, "GET", automated_path + "/content"), 200)
            expect(request(control_base, "DELETE", "/api/v1/control-tower/service-accounts/" + automation + "/tokens/" + credential["token_id"], cookie=cookie), 204)
            expect(request(control_base, "GET", automated_path), 410)
            expect(request(control_base, "GET", automated_path + "/content"), 410)
            print("PASS: automation share identity, signed access and credential revocation")

            upload = expect(request(
                control_base, "POST", prefix + "/uploads",
                {"path": "upload.txt", "size": 3, "overwrite": False}, cookie=cookie,
            ), 201)
            upload_id = json.loads(upload[1])["upload_id"]
            node_upload = "/api/v1/mounts/files/files/uploads/" + upload_id
            upload_path = prefix + "/uploads/" + upload_id
            visible = expect(request(
                control_base, "GET", upload_path, cookie=cookie,
                headers={"X-Jolt-Internal-Upload-Binding": "1"},
            ), 200)[1]
            assert b"authorization_actor_id" not in visible and b"authorization_credential_id" not in visible and b"authorization_revision" not in visible
            chunk_headers = {"Content-Range": "bytes 0-2/3"}
            expect(request(node_base, "PATCH", node_upload, b"new", token=node_token, headers=chunk_headers), 403)
            second_login = expect(request(
                control_base, "POST", "/api/v1/control-tower/auth/login",
                {"username": "admin", "password": password},
            ), 200)
            next_cookie = second_login[2]["Set-Cookie"].split(";", 1)[0]
            expect(request(control_base, "PATCH", upload_path, b"new", cookie=next_cookie, headers=chunk_headers), 409)
            expect(request(control_base, "POST", upload_path + "/authorize", {}, cookie=next_cookie), 204)
            expect(request(control_base, "PATCH", upload_path, b"new", cookie=cookie, headers=chunk_headers), 409)
            cookie = next_cookie
            expect(request(control_base, "PATCH", upload_path, b"new", cookie=cookie, headers=chunk_headers), 200)
            expect(request(control_base, "POST", upload_path + "/complete", {}, cookie=cookie), 201)
            assert expect(request(control_base, "GET", prefix + "/content?path=upload.txt", cookie=cookie), 200)[1] == b"new"
            pending = expect(request(
                control_base, "POST", prefix + "/uploads",
                {"path": "abort.txt", "size": 3, "overwrite": False}, cookie=cookie,
            ), 201)
            pending_path = prefix + "/uploads/" + json.loads(pending[1])["upload_id"]
            expect(request(control_base, "DELETE", pending_path, cookie=cookie), 204)
            assert not (root / "files" / "abort.txt").exists()
            legacy = expect(request(
                node_base, "POST", "/api/v1/mounts/files/files/uploads",
                {"path": "legacy.txt", "size": 3, "overwrite": False}, token=node_token,
            ), 201)
            legacy_path = prefix + "/uploads/" + json.loads(legacy[1])["upload_id"]
            expect(request(control_base, "PATCH", legacy_path, b"new", cookie=cookie, headers=chunk_headers), 409)
            expect(request(control_base, "POST", legacy_path + "/authorize", {}, cookie=cookie), 204)
            expect(request(control_base, "PATCH", legacy_path, b"new", cookie=cookie, headers=chunk_headers), 200)
            expect(request(control_base, "DELETE", legacy_path, cookie=cookie), 204)
            print("PASS: signed upload, credential renewal, legacy reauthorization and replay refusal")

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
                if automation_token:
                    output = output.replace(automation_token, "[redacted]")
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
