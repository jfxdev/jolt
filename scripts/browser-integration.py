#!/usr/bin/env python3
"""Run browser integration tests against two disposable nodes and a Control Tower."""

import argparse
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, stderr=subprocess.STDOUT, timeout=90
    ).strip()


def request(base, method, path, data=None, cookie=None, token=None, headers=None):
    headers = dict(headers or {})
    if isinstance(data, dict):
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data, headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def expect(response, status):
    if response[0] != status:
        raise AssertionError(
            f"Expected HTTP {status}, got {response[0]}: "
            + response[1].decode(errors="replace")[:500]
        )
    return json.loads(response[1]) if response[1] else {}


def wait_ready(base):
    for _ in range(150):
        try:
            if request(base, "GET", "/readyz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise AssertionError(f"Container did not become ready: {base}")


def node_configuration(name, alias, peer_id="", direction=""):
    grants = "transfer_grants: []\n"
    if peer_id:
        sending = direction == "send"
        permissions = "{read: true}" if sending else "{write: true}"
        conflict = "" if sending else "\n    conflict_policies: [fail, overwrite, rename, checksum]"
        grants = f"""transfer_grants:
  - id: {direction}-files
    peer_node_id: {peer_id}
    mount_id: files
    path: .
    direction: {direction}
    permissions: {permissions}{conflict}
    visible_to_peer: true
    enabled: true
"""
    return f"""version: 1
node_name: {name}
api_address: ":8080"
mtls_address: ":8443"
mtls_public_endpoint: https://{alias}:8443
data_dir: /var/lib/jolt
keys_dir: /var/lib/jolt-keys
upload_max_bytes: 67108864
upload_min_free_bytes: 0
copy_chunk_size_bytes: 65536
mounts:
  - id: files
    name: Files
    local_path: /mnt/files
    mode: read_write
    published: true
    enabled: true
{grants}"""


class HTTPSProxy:
    def __init__(self, target_port, directory):
        certificate = Path(directory) / "certificate.pem"
        key = Path(directory) / "certificate-key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(certificate), "-days", "1",
             "-subj", "/CN=127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
        target_host = "127.0.0.1"

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def proxy(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else None
                excluded = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"}
                headers = {key: value for key, value in self.headers.items() if key.lower() not in excluded}
                headers["X-Forwarded-Proto"] = "https"
                connection = http.client.HTTPConnection(target_host, target_port, timeout=120)
                try:
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    self.send_response(response.status, response.reason)
                    for key, value in response.getheaders():
                        if key.lower() not in excluded and key.lower() != "content-length":
                            self.send_header(key, value)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    while chunk := response.read(64 * 1024):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    self.close_connection = True
                    connection.close()

            do_GET = proxy
            do_POST = proxy
            do_PUT = proxy
            do_PATCH = proxy
            do_DELETE = proxy
            do_HEAD = proxy

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"https://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image", default="jolt-node:smoke")
    parser.add_argument("--control-image", default="jolt-control:smoke")
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    network = "jolt-browser-" + secrets.token_hex(8)
    names = []
    network_created = False
    proxy = None
    temporary = tempfile.TemporaryDirectory(prefix="jolt-browser-")
    root = Path(temporary.name)
    root.chmod(0o755)
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(mode=0o755)
    tokens = {"a": secrets.token_hex(32), "b": secrets.token_hex(32)}
    password = secrets.token_hex(24)
    secret_values = {
        "node-a-token": tokens["a"],
        "node-b-token": tokens["b"],
        "admin-password": password,
        "control-db-key": secrets.token_hex(32),
        "node-a-state-key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "node-b-state-key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "empty": "",
    }
    for name, value in secret_values.items():
        path = secrets_dir / name
        path.write_text(value + "\n")
        path.chmod(0o444)
    configs = {"a": root / "node-a.yaml", "b": root / "node-b.yaml"}
    for suffix, config in configs.items():
        config.write_text(node_configuration(f"node-{suffix}", f"node-{suffix}"))

    try:
        docker("network", "create", network)
        network_created = True
        common = ["--detach", "--network", network, "--security-opt", "no-new-privileges:true",
                  "--cap-drop", "ALL"]
        for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"):
            common += ["--cap-add", capability]
        bases = {}
        for suffix in ("a", "b"):
            name = f"{network}-node-{suffix}"
            names.append(name)
            docker(
                "run", *common, "--name", name, "--network-alias", f"node-{suffix}",
                "--publish", "127.0.0.1::8080", "--volume", "/mnt/files",
                "--env", "JOLT_OWNED_PATHS=/mnt/files",
                "--env", "CONTROL_TOWER_TOKEN_FILE=/run/secrets/token",
                "--env", "JOLT_STATE_ENCRYPTION_KEY_FILE=/run/secrets/state-key",
                "--env", "METRICS_TOKEN_FILE=/run/secrets/empty",
                "--mount", f"type=bind,src={configs[suffix]},dst=/etc/jolt/node.yaml,readonly",
                "--mount", f"type=bind,src={secrets_dir / ('node-' + suffix + '-token')},dst=/run/secrets/token,readonly",
                "--mount", f"type=bind,src={secrets_dir / ('node-' + suffix + '-state-key')},dst=/run/secrets/state-key,readonly",
                "--mount", f"type=bind,src={secrets_dir / 'empty'},dst=/run/secrets/empty,readonly",
                args.node_image,
            )
            bases[suffix] = "http://" + docker("port", name, "8080/tcp").splitlines()[0]
            wait_ready(bases[suffix])

        node_metadata = {}
        for suffix in ("a", "b"):
            metadata = expect(request(bases[suffix], "GET", "/api/v1/node", token=tokens[suffix]), 200)
            node_metadata[suffix] = metadata
            if args.expected_version and metadata["build"]["version"] != args.expected_version:
                raise AssertionError("Node build version does not match the release")
        node_ids = {suffix: metadata["node_id"] for suffix, metadata in node_metadata.items()}

        control_name = network + "-control"
        names.append(control_name)
        docker(
            "run", *common, "--name", control_name, "--publish", "127.0.0.1::8090",
            "--env", "CONTROL_TOWER_ADMIN_PASSWORD_FILE=/run/secrets/admin-password",
            "--env", "CONTROL_TOWER_DB_ENCRYPTION_KEY_FILE=/run/secrets/control-db-key",
            "--env", "CONTROL_TOWER_METRICS_TOKEN_FILE=/run/secrets/empty",
            "--env", "CONTROL_TOWER_SECURE_COOKIES=true",
            "--mount", f"type=bind,src={secrets_dir / 'admin-password'},dst=/run/secrets/admin-password,readonly",
            "--mount", f"type=bind,src={secrets_dir / 'control-db-key'},dst=/run/secrets/control-db-key,readonly",
            "--mount", f"type=bind,src={secrets_dir / 'empty'},dst=/run/secrets/empty,readonly",
            args.control_image,
        )
        control_http = "http://" + docker("port", control_name, "8090/tcp").splitlines()[0]
        wait_ready(control_http)
        login = request(control_http, "POST", "/api/v1/control-tower/auth/login",
                        {"username": "admin", "password": password})
        expect(login, 200)
        cookie = login[2]["Set-Cookie"].split(";", 1)[0]
        for suffix in ("a", "b"):
            expect(request(control_http, "POST", "/api/v1/control-tower/nodes", {
                "name": f"Node {suffix.upper()}",
                "endpoint": f"http://node-{suffix}:8080",
                "token": tokens[suffix],
            }, cookie=cookie), 201)
        connection = expect(request(control_http, "POST", "/api/v1/control-tower/connections", {
            "issuer_node_id": node_ids["a"],
            "target_node_id": node_ids["b"],
            "transfer_mode": "dual_channel",
            "issuer_role": "sender_receiver",
            "invitee_role": "sender_receiver",
            "purpose": "Browser integration transfer qualification",
            "expiry_minutes": 20,
        }, cookie=cookie), 201)
        if not connection["trust_established"]:
            connection = expect(request(
                control_http, "POST",
                f"/api/v1/control-tower/connections/{connection['request']['request_id']}/approve",
                {"confirmed_fingerprint": node_metadata["a"]["fingerprint"]}, cookie=cookie,
            ), 200)
        if not connection["trust_established"]:
            raise AssertionError("Node pairing did not establish bilateral mTLS trust")

        configs["a"].write_text(node_configuration("node-a", "node-a", node_ids["b"], "send"))
        configs["b"].write_text(node_configuration("node-b", "node-b", node_ids["a"], "receive"))
        for suffix in ("a", "b"):
            name = f"{network}-node-{suffix}"
            docker("restart", name)
            wait_ready(bases[suffix])

        if args.expected_version:
            about = expect(request(control_http, "GET", "/api/v1/control-tower/about", cookie=cookie), 200)
            if about["version"] != args.expected_version:
                raise AssertionError("Control build version does not match the release")

        proxy = HTTPSProxy(int(control_http.rsplit(":", 1)[1]), root)
        environment = os.environ.copy()
        environment.update({
            "JOLT_INTEGRATION_BASE_URL": proxy.base_url,
            "JOLT_INTEGRATION_ADMIN_PASSWORD": password,
            "JOLT_INTEGRATION_NODE_A_ID": node_ids["a"],
            "JOLT_INTEGRATION_NODE_B_ID": node_ids["b"],
            "JOLT_INTEGRATION_NODE_A_TOKEN": tokens["a"],
            "JOLT_INTEGRATION_NODE_B_TOKEN": tokens["b"],
        })
        subprocess.run(
            ["npm", "run", "test:e2e:integration"],
            cwd=Path(__file__).resolve().parent.parent / "control" / "frontend",
            env=environment, check=True, timeout=900,
        )
    except Exception:
        for name in names:
            logs = docker("logs", "--tail", "40", name)
            for secret in [*tokens.values(), password]:
                logs = logs.replace(secret, "[redacted]")
            print(logs)
        raise
    finally:
        if proxy:
            proxy.close()
        for name in reversed(names):
            docker("rm", "--force", "--volumes", name)
        if network_created:
            docker("network", "rm", network)
        temporary.cleanup()


if __name__ == "__main__":
    main()
