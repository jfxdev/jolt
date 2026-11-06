#!/usr/bin/env python3
"""Enroll real nodes in a real Control Tower's certificate authority.

Build both binaries first and pass their paths with --node-bin and --control-bin.
Requires OpenSSL. No existing state is modified: everything lives in a
temporary directory, on loopback, on free ports.

It checks what only real processes can show: the join token's pin against a
live root, a node that serves HTTPS with the certificate it was issued, the
Control Tower reaching it over that connection, the spent token refused, a
restart that needs no token, an enrollment a person approves, and a node whose
token pins the wrong root sending nothing.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def freeport():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Client:
    def __init__(self, base, cafile=None):
        self.base = base
        self.context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        self.cookie = None

    def call(self, method, path, body=None, token=None, headers=None):
        headers = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10, context=self.context) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as response:
            return response.code, response.read(), response.headers

    def json(self, method, path, body=None, expect=200, **kw):
        status, data, _ = self.call(method, path, body, **kw)
        if status != expect:
            raise RuntimeError(f"{method} {path}: expected {expect}, got {status}: {data[:400]!r}")
        return json.loads(data) if data else None


def wait(condition, what, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if condition():
                return
        except (OSError, RuntimeError, urllib.error.URLError, ssl.SSLError):
            pass
        time.sleep(0.2)
    raise RuntimeError("timed out waiting for " + what)


def read_log(path):
    return Path(path).read_text() if Path(path).exists() else ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-bin", required=True)
    parser.add_argument("--control-bin", required=True)
    args = parser.parse_args()
    processes = []
    try:
        with tempfile.TemporaryDirectory(prefix="jolt-managed-smoke-") as temp:
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


def start(command, env, log, processes):
    handle = open(log, "wb")
    process = subprocess.Popen(command, env=env, stdout=handle, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def node_files(root, name, api, mtls, extra=""):
    directory = root / name
    (directory / "files").mkdir(parents=True)
    config = directory / "node.yaml"
    config.write_text(f'''version: 1
node_name: {name}
tls_mode: managed
api_public_endpoint: "https://127.0.0.1:{api}"
api_address: "127.0.0.1:{api}"
mtls_address: "127.0.0.1:{mtls}"
mtls_public_endpoint: "https://127.0.0.1:{mtls}"
data_dir: "{directory / 'state'}"
keys_dir: "{directory / 'keys'}"
{extra}
mounts:
  - id: files
    name: Files
    local_path: "{directory / 'files'}"
    mode: read_write
    published: true
    enabled: true
transfer_grants: []
''')
    return directory, config


def node_env(token=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CONTROL_TOWER_", "JOLT_"))}
    env["JOLT_STATE_ENCRYPTION_KEY"] = base64.b64encode(bytes(range(32))).decode()
    if token:
        env["JOLT_JOIN_TOKEN"] = token
    return env


def run(root, args, processes):
    port = freeport()
    control_url = f"https://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CONTROL_TOWER_", "JOLT_"))}
    env.update({
        "CONTROL_TOWER_TLS_MODE": "managed", "CONTROL_TOWER_ADDRESS": f"127.0.0.1:{port}", "CONTROL_TOWER_CA_ADDRESS": "off",
        "CONTROL_TOWER_PUBLIC_BASE_URL": control_url, "CONTROL_TOWER_DATA_DIR": str(root / "control"),
        "CONTROL_TOWER_ADMIN_PASSWORD": "smoke-admin-password", "CONTROL_TOWER_DB_ENCRYPTION_KEY": "smoke-encryption-key-that-is-long-enough-1234",
        "CONTROL_TOWER_STATIC_DIR": str(root),
    })
    start([args.control_bin], env, root / "control.log", processes)
    insecure = Client(control_url)
    insecure.context = ssl._create_unverified_context()
    wait(lambda: insecure.call("GET", "/health")[0] == 200, "the Control Tower to start")

    # What a person or an agent does first: take the root, confirm its fingerprint.
    status, root_pem, _ = insecure.call("GET", "/.well-known/jolt/ca.pem")
    assert status == 200 and b"BEGIN CERTIFICATE" in root_pem
    (root / "root.pem").write_bytes(root_pem)
    fingerprint = subprocess.check_output(["openssl", "x509", "-in", str(root / "root.pem"), "-noout", "-fingerprint", "-sha256"]).decode()
    pin = fingerprint.split("=")[1].replace(":", "").strip().lower()
    control = Client(control_url, cafile=str(root / "root.pem"))
    # The login sets a cookie; urllib does not keep one, so carry it by hand.
    status, _, headers = control.call("POST", "/api/v1/control-tower/auth/login", {"username": "admin", "password": "smoke-admin-password"})
    assert status == 200, status
    control.cookie = headers["Set-Cookie"].split(";")[0]
    print("ok   the Control Tower serves HTTPS under the root it publishes")

    def make_token(name, approval=None):
        body = {"node_name": name}
        if approval:
            body["approval"] = approval
        return control.json("POST", "/api/v1/control-tower/enrollments/tokens", body, expect=201)

    # 1. An automatic enrollment.
    api, mtls = freeport(), freeport()
    token = make_token("alpha")
    assert token["token"].split(":")[3] == pin, "the token does not pin the published root"
    directory, config = node_files(root, "alpha", api, mtls)
    node = start([args.node_bin, "--config", str(config)], node_env(token["token"]), root / "alpha.log", processes)
    wait(lambda: "enrolled" in read_log(root / "alpha.log"), "alpha to enroll")
    node_client = Client(f"https://127.0.0.1:{api}", cafile=str(root / "root.pem"))
    wait(lambda: node_client.call("GET", "/health")[0] in (200, 401), "alpha's API over HTTPS")
    print("ok   a node enrolled with a one-use token and serves HTTPS with its own certificate")

    assert node_client.call("GET", "/api/v1/node")[0] == 401, "the node's API answered without a token"
    assert node_client.call("GET", "/api/v1/node", token="wrong")[0] == 401
    plain = Client(f"https://127.0.0.1:{api}")  # system trust only: must not trust the node
    try:
        plain.call("GET", "/health")
        raise AssertionError("a client that does not know the root reached the node")
    except (urllib.error.URLError, ssl.SSLError):
        pass
    print("ok   the node's API refuses a missing or wrong token, and only the authority's root trusts it")

    nodes = control.json("GET", "/api/v1/control-tower/nodes")["items"]
    assert len(nodes) == 1 and nodes[0]["name"] == "alpha" and nodes[0]["endpoint"] == f"https://127.0.0.1:{api}", nodes
    node_id = nodes[0]["node_id"]
    wait(lambda: control.call("GET", f"/api/v1/nodes/{node_id}/mounts")[0] == 200, "the Control Tower to reach the node")
    print("ok   the Control Tower registered the node and reaches it over the issued certificate")

    managed = control.json("GET", "/api/v1/control-tower/crypto/ca")
    assert any(item["kind"] == "client" for item in managed["items"])

    # 2. The token is spent.
    csr = subprocess.check_output(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=" + node_id,
                                   "-keyout", os.devnull], stderr=subprocess.DEVNULL).decode()
    secret = token["token"].split(":")[2]
    spent = insecure.call("POST", "/api/v1/control-tower/enroll", {
        "secret": secret, "node_name": "alpha", "node_id": node_id, "node_fingerprint": "x", "api_endpoint": f"https://127.0.0.1:{api}",
        "csr_pem": csr, "operational_token": "o" * 43})
    assert spent[0] == 401, spent
    print("ok   a spent token enrolls nothing else")

    # 3. A restart needs no token, and a leftover one is ignored.
    node.terminate()
    node.wait(timeout=15)
    node = start([args.node_bin, "--config", str(config)], node_env(token["token"]), root / "alpha2.log", processes)
    wait(lambda: node_client.call("GET", "/health")[0] in (200, 401), "alpha to come back")
    assert "already enrolled" in read_log(root / "alpha2.log")
    wait(lambda: control.call("GET", f"/api/v1/nodes/{node_id}/mounts")[0] == 200, "the Control Tower to reach the restarted node")
    node.terminate()
    node.wait(timeout=15)
    node = start([args.node_bin, "--config", str(config)], node_env(), root / "alpha3.log", processes)
    wait(lambda: control.call("GET", f"/api/v1/nodes/{node_id}/mounts")[0] == 200, "the node to serve with no token in its environment")
    print("ok   a restart needs no token, and the node keeps its certificate and its operational token")
    node.terminate()
    node.wait(timeout=15)

    # 4. A token that pins the wrong root: nothing is sent.
    wrong = make_token("mallory")["token"].split(":")
    wrong[3] = "0" * 64
    api2, mtls2 = freeport(), freeport()
    _, config2 = node_files(root, "mallory", api2, mtls2)
    bad = start([args.node_bin, "--config", str(config2)], node_env(":".join(wrong)), root / "mallory.log", processes)
    bad.wait(timeout=40)
    log = read_log(root / "mallory.log")
    assert bad.returncode != 0 and "fingerprint" in log, log[-600:]
    pending = control.json("GET", "/api/v1/control-tower/enrollments")["items"]
    assert all(item["node_name"] != "mallory" for item in pending), "the secret reached the server"
    print("ok   a node whose token pins another root refuses to send its secret")

    # 5. An enrollment that waits for a person.
    api3, mtls3 = freeport(), freeport()
    manual = make_token("beta", "manual")
    _, config3 = node_files(root, "beta", api3, mtls3)
    waiting = start([args.node_bin, "--config", str(config3)], node_env(manual["token"]), root / "beta.log", processes)
    wait(lambda: any(item["state"] == "pending" for item in control.json("GET", "/api/v1/control-tower/enrollments?state=pending")["items"]), "beta to wait")
    item = control.json("GET", "/api/v1/control-tower/enrollments?state=pending")["items"][0]
    assert item["node_name"] == "beta" and item["node_fingerprint"], item
    assert item["node_fingerprint"] in read_log(root / "beta.log"), "the fingerprint a person compares is not in the node's log"
    assert waiting.poll() is None
    control.json("POST", f"/api/v1/control-tower/enrollments/{item['enrollment_id']}/approve")
    wait(lambda: "enrolled" in read_log(root / "beta.log"), "beta to enroll after approval", seconds=40)
    beta = Client(f"https://127.0.0.1:{api3}", cafile=str(root / "root.pem"))
    wait(lambda: beta.call("GET", "/health")[0] in (200, 401), "beta's API")
    print("ok   a node waits for a person, whose approval enrolls it")

    names = sorted(entry["name"] for entry in control.json("GET", "/api/v1/control-tower/nodes")["items"])
    assert names == ["alpha", "beta"], names
    print("ok   done")


if __name__ == "__main__":
    main()
