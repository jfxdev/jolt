#!/usr/bin/env python3
"""Rehearse snapshot, empty restore, upgrade and backup-compatible rollback."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, timeout=120
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
        raise AssertionError(f"Expected {status}, got {response[0]}: {response[1][:500]!r}")
    return json.loads(response[1]) if response[1] else {}


def wait_ready(base):
    for _ in range(150):
        try:
            if request(base, "GET", "/readyz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise AssertionError(f"Service not ready: {base}")


def login(base, password):
    response = request(base, "POST", "/api/v1/control-tower/auth/login",
                       {"username": "admin", "password": password})
    expect(response, 200)
    return response[2]["Set-Cookie"].split(";", 1)[0]


def configuration():
    return """version: 1
node_name: lifecycle
api_address: ":8080"
mtls_address: ":8443"
mtls_public_endpoint: https://node-lifecycle:8443
data_dir: /var/lib/jolt
keys_dir: /var/lib/jolt-keys
upload_max_bytes: 1048576
upload_min_free_bytes: 0
mounts:
  - id: files
    name: Files
    local_path: /mnt/files
    mode: read_write
    published: true
    enabled: true
transfer_grants: []
"""


def extract(archive, destination):
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as bundle:
        root = destination.resolve()
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if root != target and root not in target.parents:
                raise AssertionError("Snapshot path escapes its restore directory")
            if member.issym() or member.islnk():
                raise AssertionError("Snapshot links are not supported by this rehearsal")
        bundle.extractall(destination, filter="data")
    for path in destination.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)


class Lifecycle:
    def __init__(self, args):
        self.args = args
        self.network = "jolt-lifecycle-" + secrets.token_hex(8)
        self.names = []
        self.temporary = tempfile.TemporaryDirectory(prefix="jolt-lifecycle-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        self.backup = self.root / "backups"
        self.backup.mkdir(mode=0o777)
        self.backup.chmod(0o777)
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o755)
        self.node_token = secrets.token_hex(32)
        self.password = secrets.token_hex(24)
        values = {
            "node-token": self.node_token,
            "node-key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "admin-password": self.password,
            "control-key": secrets.token_hex(32),
            "empty": "",
        }
        for name, value in values.items():
            path = self.secrets / name
            path.write_text(value + "\n")
            path.chmod(0o444)

    def common(self):
        result = ["--detach", "--network", self.network, "--security-opt", "no-new-privileges:true",
                  "--cap-drop", "ALL", "--env", f"PUID={os.getuid()}", "--env", f"PGID={os.getgid()}"]
        for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"):
            result += ["--cap-add", capability]
        return result

    def start(self, state, node_image, control_image):
        node_name = self.network + "-" + state.name + "-node"
        control_name = self.network + "-" + state.name + "-control"
        self.names += [node_name, control_name]
        config = state / "node.yaml"
        docker(
            "run", *self.common(), "--name", node_name, "--network-alias", "node-lifecycle",
            "--publish", "127.0.0.1::8080",
            "--env", "CONTROL_TOWER_TOKEN_FILE=/run/secrets/node-token",
            "--env", "JOLT_STATE_ENCRYPTION_KEY_FILE=/run/secrets/node-key",
            "--env", "METRICS_TOKEN_FILE=/run/secrets/empty",
            "--env", "JOLT_OWNED_PATHS=/mnt/files",
            "--mount", f"type=bind,src={config},dst=/etc/jolt/node.yaml,readonly",
            "--mount", f"type=bind,src={state / 'data'},dst=/var/lib/jolt",
            "--mount", f"type=bind,src={state / 'keys'},dst=/var/lib/jolt-keys",
            "--mount", f"type=bind,src={self.root / 'files'},dst=/mnt/files",
            "--mount", f"type=bind,src={self.secrets / 'node-token'},dst=/run/secrets/node-token,readonly",
            "--mount", f"type=bind,src={self.secrets / 'node-key'},dst=/run/secrets/node-key,readonly",
            "--mount", f"type=bind,src={self.secrets / 'empty'},dst=/run/secrets/empty,readonly",
            node_image,
        )
        docker(
            "run", *self.common(), "--name", control_name, "--publish", "127.0.0.1::8090",
            "--env", "CONTROL_TOWER_ADMIN_PASSWORD_FILE=/run/secrets/admin-password",
            "--env", "CONTROL_TOWER_DB_ENCRYPTION_KEY_FILE=/run/secrets/control-key",
            "--env", "CONTROL_TOWER_METRICS_TOKEN_FILE=/run/secrets/empty",
            "--env", "CONTROL_TOWER_SECURE_COOKIES=false",
            "--mount", f"type=bind,src={state / 'control'},dst=/var/lib/jolt-control",
            "--mount", f"type=bind,src={self.secrets / 'admin-password'},dst=/run/secrets/admin-password,readonly",
            "--mount", f"type=bind,src={self.secrets / 'control-key'},dst=/run/secrets/control-key,readonly",
            "--mount", f"type=bind,src={self.secrets / 'empty'},dst=/run/secrets/empty,readonly",
            control_image,
        )
        node_base = "http://" + docker("port", node_name, "8080/tcp").splitlines()[0]
        control_base = "http://" + docker("port", control_name, "8090/tcp").splitlines()[0]
        wait_ready(node_base)
        wait_ready(control_base)
        return node_name, control_name, node_base, control_base

    def stop(self, *names):
        for name in reversed(names):
            docker("rm", "--force", name)
            self.names.remove(name)

    def offline_mounts(self, state, include_node=True):
        result = ["--env", f"PUID={os.getuid()}", "--env", f"PGID={os.getgid()}",
                  "--mount", f"type=bind,src={self.backup},dst=/backup"]
        if include_node:
            result += [
                "--mount", f"type=bind,src={state / 'node.yaml'},dst=/etc/jolt/node.yaml,readonly",
                "--mount", f"type=bind,src={state / 'data'},dst=/var/lib/jolt",
                "--mount", f"type=bind,src={state / 'keys'},dst=/var/lib/jolt-keys",
                "--mount", f"type=bind,src={self.root / 'files'},dst=/mnt/files",
                "--env", "JOLT_STATE_ENCRYPTION_KEY_FILE=/run/secrets/node-key",
                "--mount", f"type=bind,src={self.secrets / 'node-key'},dst=/run/secrets/node-key,readonly",
            ]
        else:
            result += [
                "--mount", f"type=bind,src={state / 'control'},dst=/var/lib/jolt-control",
                "--env", "CONTROL_TOWER_DB_ENCRYPTION_KEY_FILE=/run/secrets/control-key",
                "--mount", f"type=bind,src={self.secrets / 'control-key'},dst=/run/secrets/control-key,readonly",
            ]
        return result

    def snapshot(self, state, prefix, node_image, control_image):
        node_archive = self.backup / f"{prefix}-node.tar.gz"
        control_archive = self.backup / f"{prefix}-control.tar.gz"
        manifest = docker("run", "--rm", *self.offline_mounts(state), node_image,
                          "/usr/local/bin/jolt-node", "snapshot", "--output", "/backup/" + node_archive.name)
        node_manifest = json.loads(manifest)
        docker("run", "--rm", *self.offline_mounts(state, False), control_image,
               "/usr/local/bin/jolt-control", "snapshot", "--output", "/backup/" + control_archive.name)
        return node_archive, control_archive, node_manifest

    def restore(self, source_state, archives, destination):
        extract(archives[0], destination)
        control_stage = self.root / (destination.name + "-control-extract")
        extract(archives[1], control_stage)
        (control_stage / "data").rename(destination / "control")
        (control_stage / "manifest.json").unlink()
        control_stage.rmdir()
        if source_state != destination:
            destination.chmod(0o700)
        return destination

    def diagnose(self, state, image_node, image_control, manifest):
        result = subprocess.run(
            ["docker", "run", "--rm", *self.offline_mounts(state), image_node,
             "/usr/local/bin/jolt-node", "restore-diagnostics", "--expected-node-id", manifest["node_id"],
             "--expected-fingerprint", manifest["fingerprint"]],
            text=True, capture_output=True, timeout=120,
        )
        report = json.loads(result.stdout)
        if result.returncode != 0 or report["status"] == "error":
            raise AssertionError(f"Node restore diagnostics failed: {report}")
        result = subprocess.run(
            ["docker", "run", "--rm", *self.offline_mounts(state, False), image_control,
             "/usr/local/bin/jolt-control", "restore-diagnostics"],
            text=True, capture_output=True, timeout=120,
        )
        report = json.loads(result.stdout)
        if result.returncode != 0 or report["status"] == "error":
            raise AssertionError(f"Control restore diagnostics failed: {report}")

    def close(self):
        for name in reversed(self.names):
            docker("rm", "--force", name)
        docker("network", "rm", self.network)
        self.temporary.cleanup()


def verify_operation(node_base, control_base, token, password, node_id, pending=None):
    metadata = expect(request(node_base, "GET", "/api/v1/node", token=token), 200)
    if metadata["node_id"] != node_id:
        raise AssertionError("Node identity changed")
    cookie = login(control_base, password)
    inventory = expect(request(control_base, "GET", "/api/v1/control-tower/nodes", cookie=cookie), 200)
    if not any(item["node_id"] == node_id for item in inventory["items"]):
        raise AssertionError("Restored Control Tower lost the node registration")
    policies = expect(request(control_base, "GET", "/api/v1/control-tower/policies", cookie=cookie), 200)
    if not any(item["name"] == "lifecycle-policy" for item in policies.get("items", [])):
        raise AssertionError("Restored Control Tower lost policies")
    path = "/api/v1/mounts/files/files"
    content = request(node_base, "GET", path + "/content?path=hello.txt", token=token)
    if content[0] != 200 or content[1] != b"lifecycle":
        raise AssertionError("Published mount content is unavailable")
    if pending:
        resumed = expect(request(node_base, "GET", path + "/uploads/" + pending, token=token), 200)
        offset = resumed["offset"]
        suffix = b"lifecycle"[offset:]
        expect(request(node_base, "PATCH", path + "/uploads/" + pending, suffix, token=token,
                       headers={"Content-Type": "application/octet-stream",
                                "Content-Range": f"bytes {offset}-8/9"}), 200)
        expect(request(node_base, "POST", path + "/uploads/" + pending + "/complete", {}, token=token), 201)
        if request(node_base, "GET", path + "/content?path=resume.txt", token=token)[1] != b"lifecycle":
            raise AssertionError("Resumable upload did not survive lifecycle")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image", default="jolt-node:smoke")
    parser.add_argument("--control-image", default="jolt-control:smoke")
    parser.add_argument("--previous-node-image")
    parser.add_argument("--previous-control-image")
    args = parser.parse_args()
    previous_node = args.previous_node_image or args.node_image
    previous_control = args.previous_control_image or args.control_image
    if (args.previous_node_image is None) != (args.previous_control_image is None):
        parser.error("previous node and control images must be supplied together")

    life = Lifecycle(args)
    original = life.root / "original"
    (original / "data").mkdir(parents=True)
    (original / "keys").mkdir()
    (original / "control").mkdir()
    (life.root / "files").mkdir()
    (original / "node.yaml").write_text(configuration())
    try:
        docker("network", "create", life.network)
        node_name, control_name, node_base, control_base = life.start(original, previous_node, previous_control)
        metadata = expect(request(node_base, "GET", "/api/v1/node", token=life.node_token), 200)
        node_id = metadata["node_id"]
        cookie = login(control_base, life.password)
        expect(request(control_base, "POST", "/api/v1/control-tower/nodes", {
            "name": "Lifecycle", "endpoint": "http://node-lifecycle:8080", "token": life.node_token,
        }, cookie=cookie), 201)
        expect(request(control_base, "POST", "/api/v1/control-tower/policies", {
            "name": "lifecycle-policy", "rules": [{"path": f"nodes/{node_id}/files/mounts/files/**", "capabilities": ["read"]}],
        }, cookie=cookie), 201)
        path = "/api/v1/mounts/files/files"
        expect(request(node_base, "PUT", path + "/content?path=hello.txt", b"lifecycle", token=life.node_token), 201)
        upload = expect(request(node_base, "POST", path + "/uploads", {
            "path": "resume.txt", "size": 9, "overwrite": False,
        }, token=life.node_token), 201)
        upload_id = upload["upload_id"]
        expect(request(node_base, "PATCH", path + "/uploads/" + upload_id, b"life", token=life.node_token,
                       headers={"Content-Type": "application/octet-stream", "Content-Range": "bytes 0-3/9"}), 200)
        life.stop(control_name, node_name)
        archives = life.snapshot(original, "previous", previous_node, previous_control)

        restored = life.restore(original, archives, life.root / "restored")
        life.diagnose(restored, args.node_image, args.control_image, archives[2])
        node_name, control_name, node_base, control_base = life.start(restored, args.node_image, args.control_image)
        verify_operation(node_base, control_base, life.node_token, life.password, node_id, upload_id)
        life.stop(control_name, node_name)
        print("PASS: snapshot, empty restore, diagnostics and resumed operation")

        upgraded = life.restore(original, archives, life.root / "upgraded")
        node_name, control_name, node_base, control_base = life.start(upgraded, args.node_image, args.control_image)
        verify_operation(node_base, control_base, life.node_token, life.password, node_id)
        life.stop(control_name, node_name)
        print("PASS: candidate images operate on the previous compatible state")

        rollback = life.restore(original, archives, life.root / "rollback")
        life.diagnose(rollback, previous_node, previous_control, archives[2])
        node_name, control_name, node_base, control_base = life.start(rollback, previous_node, previous_control)
        verify_operation(node_base, control_base, life.node_token, life.password, node_id)
        life.stop(control_name, node_name)
        print("PASS: rollback uses previous images with their compatible backup")
    except Exception:
        for name in life.names:
            logs = docker("logs", "--tail", "40", name)
            print(logs.replace(life.node_token, "[redacted]").replace(life.password, "[redacted]"))
        raise
    finally:
        life.close()


if __name__ == "__main__":
    main()
