#!/usr/bin/env python3
"""Exercise the real Control Tower -> node boundary with disposable data.

Build jolt-node:smoke and jolt-control:smoke before running. Only a temporary read-only configuration file
is mounted, credentials are random, ports bind only to loopback, and only the
containers/network created by this invocation are removed.
"""

import argparse
import base64
import hashlib
import tempfile
from pathlib import Path
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, stderr=subprocess.STDOUT, timeout=60
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
        with urllib.request.urlopen(req, timeout=20) as response:
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
    for _ in range(100):
        try:
            if request(base, "GET", "/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise AssertionError("Container did not become healthy")


def login(base, username, password):
    response = request(
        base, "POST", "/api/v1/control-tower/auth/login",
        {"username": username, "password": password},
    )
    expect(response, 200)
    return response[2]["Set-Cookie"].split(";", 1)[0]


def exercise(node_base, control_base, node_name, node_token, password, expected_version=None):
    wait_ready(node_base)
    wait_ready(control_base)
    admin = login(control_base, "admin", password)
    if expected_version:
        about = expect(request(control_base, "GET", "/api/v1/control-tower/about", cookie=admin), 200)
        if about["version"] != expected_version:
            raise AssertionError(f"Control build version {about['version']} != {expected_version}")

    def control(method, path, body=None, cookie=admin, **kwargs):
        return request(control_base, method, path, body, cookie=cookie, **kwargs)

    def node(method, path, body=None, **kwargs):
        return request(node_base, method, path, body, token=node_token, **kwargs)

    registered = expect(control("POST", "/api/v1/control-tower/nodes", {
        "name": "Smoke node", "endpoint": "http://node-smoke:8080", "token": node_token,
    }), 201)
    node_id = registered["node_id"]
    metadata = expect(node("GET", "/api/v1/node"), 200)
    assert metadata["configuration"]["source"] == "yaml"
    if expected_version and metadata["build"]["version"] != expected_version:
        raise AssertionError(f"Node build version {metadata['build']['version']} != {expected_version}")
    mount = expect(node("GET", "/api/v1/mounts/files"), 200)
    mount_id = mount["mount_id"]
    for method, path in [("POST", "/api/v1/mounts"), ("PUT", "/api/v1/mounts/files"),
                         ("DELETE", "/api/v1/mounts/files"), ("POST", "/api/v1/grants")]:
        error = expect(node(method, path, {}), 409)
        assert "configuration_managed_by_file" in str(error)
    print("PASS: YAML resources are visible and immutable through the API")
    direct = f"/api/v1/mounts/{mount_id}/files"
    proxied = f"/api/v1/nodes/{node_id}/mounts/{mount_id}/files"

    for path in ("public", "private", "docs", "docs/private"):
        job = expect(node("POST", direct + "/directories", {"path": path}), 202)
        for _ in range(100):
            current = expect(node("GET", "/api/v1/jobs/" + job["job_id"]), 200)
            if current["state"] == "completed":
                break
            if current["state"] in ("failed", "cancelled", "completed_with_warnings"):
                raise AssertionError("Directory job failed: " + str(current.get("error")))
            time.sleep(0.1)
        else:
            raise AssertionError("Directory job did not complete")
    expect(node("PUT", direct + "/content?path=private/secret.txt", b"fictional-secret"), 201)

    operator_password = secrets.token_hex(24)
    operator = expect(control("POST", "/api/v1/control-tower/users", {
        "username": "restricted", "password": operator_password, "role": "operator",
    }), 201)
    scope = f"nodes/{node_id}/files/mounts/{mount_id}"
    policy = expect(control("POST", "/api/v1/control-tower/policies", {
        "name": "smoke-policy", "rules": [
            {"path": scope + "/**", "capabilities": ["read", "list", "create", "update", "delete"]},
            {"path": scope + "/private/**", "capabilities": ["deny"]},
            {"path": scope + "/docs/private/**", "capabilities": ["deny"]},
            {"path": f"nodes/{node_id}/jobs", "capabilities": ["create"]},
        ],
    }), 201)
    expect(control("PUT", "/api/v1/control-tower/users/" + operator["user_id"] + "/policies",
                   {"policy_ids": [policy["policy_id"]]}), 200)
    restricted = login(control_base, "restricted", operator_password)
    expect(control("GET", proxied + "/content?path=private/secret.txt", cookie=restricted), 403)
    for method, path, body in [
        ("POST", "/copy", {"source_path": "docs", "destination_path": "copy"}),
        ("POST", "/move", {"source_path": "docs", "destination_path": "moved"}),
        ("DELETE", "?path=docs&recursive=true", None),
    ]:
        expect(control(method, proxied + path, body, cookie=restricted), 403)
    print("PASS: recursive copy/move/delete enforce descendant deny rules")

    session = expect(control("POST", proxied + "/uploads", {
        "path": "public/hello.txt", "size": 4, "overwrite": False,
    }, cookie=restricted), 201)
    upload_path = proxied + "/uploads/" + session["upload_id"]
    headers = {"Content-Type": "application/octet-stream", "Content-Range": "bytes 0-3/4"}
    expect(control("PATCH", upload_path, b"jolt", cookie=restricted, headers=headers), 200)
    verification = expect(control("GET", upload_path + "/verification", cookie=restricted), 200)
    assert verification["blocks"][0]["sha256"] == hashlib.sha256(b"jolt").hexdigest()
    receipt = expect(control("POST", upload_path + "/complete", {}, cookie=restricted), 201)
    assert expect(control("POST", upload_path + "/complete", {}, cookie=restricted), 201) == receipt
    assert expect(control("GET", upload_path, cookie=restricted), 200)["state"] == "completed"
    assert expect(control("GET", proxied + "/uploads", cookie=restricted), 200)["sessions"] == []
    summary = expect(control("GET", f"/api/v1/nodes/{node_id}/jobs/summary"), 200)
    assert summary["counts"]["completed"] >= 4
    expect(control("GET", f"/api/v1/nodes/{node_id}/jobs/summary", cookie=restricted), 403)
    content = control("GET", proxied + "/content?path=public/hello.txt", cookie=restricted)
    if content[0] != 200 or content[1] != b"jolt":
        raise AssertionError("Proxied resumable upload did not preserve its bytes")
    expect(control("POST", proxied + "/uploads", {"path": "large.bin", "size": 33}), 413)
    print("PASS: operator chunk upload, completion, download and size limit")
    pending = expect(node("POST", direct + "/uploads", {"path": "public/restart.txt", "size": 4}), 201)
    resume_path = direct + "/uploads/" + pending["upload_id"]
    expect(node("PATCH", resume_path, b"jo", headers={"Content-Range": "bytes 0-1/4", "Content-Type": "application/octet-stream"}), 200)
    before = expect(node("GET", "/api/v1/node"), 200)["node_id"]
    docker("restart", node_name)
    node_base = "http://" + docker("port", node_name, "8080/tcp").splitlines()[0]
    wait_ready(node_base)
    assert expect(node("GET", "/api/v1/node"), 200)["node_id"] == before
    assert expect(node("GET", resume_path), 200)["offset"] == 2
    expect(node("PATCH", resume_path, b"lt", headers={"Content-Range": "bytes 2-3/4", "Content-Type": "application/octet-stream"}), 200)
    expect(node("POST", resume_path + "/complete", {}), 201)
    assert node("GET", direct + "/content?path=public/restart.txt")[1] == b"jolt"
    completed = expect(node("GET", resume_path), 200)
    assert completed["state"] == "completed" and completed["offset"] == 4
    assert docker("exec", node_name, "sh", "-c", "find /var/lib/jolt -name '*.db*'") == ""
    print("PASS: identity and upload checkpoints survive restart without database files")


    private = expect(control("POST", proxied + "/uploads", {
        "path": "private/upload.txt", "size": 4,
    }), 201)
    private_path = proxied + "/uploads/" + private["upload_id"]
    for method in ("GET", "PATCH", "POST", "DELETE"):
        path = private_path + ("/complete" if method == "POST" else "")
        body = {} if method == "POST" else None
        expect(control(method, path + "?path=public/hello.txt", body, cookie=restricted), 403)
    listing = expect(control("GET", proxied + "/uploads", cookie=restricted), 200)
    if listing["sessions"]:
        raise AssertionError("Restricted operator saw a private upload session")
    expect(control("DELETE", private_path), 204)
    print("PASS: persisted upload destination defeats decoy paths and session listing leaks")

    docker("exec", "--user", "1000:1000", node_name, "ln", "-s",
           "../private/secret.txt", "/mnt/files/public/alias.txt")
    share = expect(control("POST", "/api/v1/control-tower/shares", {
        "node_id": node_id, "mount_id": mount_id, "path": "public", "kind": "directory",
    }), 201)
    response = request(control_base, "GET",
                       "/api/v1/public/shares/" + share["token"] + "/content?path=alias.txt")
    expect(response, 400)
    if b"fictional-secret" in response[1]:
        raise AssertionError("Public share followed a symlink outside its folder")
    print("PASS: anonymous folder share cannot follow a symlink outside its scope")

    limited = expect(control("POST", "/api/v1/control-tower/shares", {
        "node_id": node_id, "mount_id": mount_id, "path": "public/hello.txt",
        "kind": "file", "max_downloads": 1,
    }), 201)
    url = "/api/v1/public/shares/" + limited["token"] + "/content"
    first = request(control_base, "GET", url, headers={"Range": "bytes=1-"})
    if first[0] != 206 or first[1] != b"olt":
        raise AssertionError("Initial ranged download failed")
    expect(request(control_base, "GET", url, headers={"Range": "bytes=1-"}), 410)
    if request(control_base, "GET", "/")[0] != 200:
        raise AssertionError("Frontend assets are unavailable")
    print("PASS: ranged requests consume download budget; frontend assets load")

    rotation = expect(control("POST", f"/api/v1/control-tower/nodes/{node_id}/rotate-token", {}), 200)
    assert rotation["old_token_invalidated"] is True
    expect(node("GET", "/api/v1/node"), 401)
    expect(control("GET", proxied + "/metadata?path=public/hello.txt"), 200)
    print("PASS: token rotation persists the new credential and rejects the old token")



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image", default="jolt-node:smoke")
    parser.add_argument("--control-image", default="jolt-control:smoke")
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    network = "jolt-smoke-" + secrets.token_hex(8)
    names = []
    network_created = False
    configuration = tempfile.TemporaryDirectory(prefix="jolt-smoke-config-")
    config_path = Path(configuration.name) / "node.yaml"
    config_path.write_text("""version: 1
node_name: smoke
api_address: ":8080"
mtls_address: ":8443"
mtls_public_endpoint: https://node-smoke:8443
data_dir: /var/lib/jolt
keys_dir: /var/lib/jolt-keys
upload_max_bytes: 32
upload_min_free_bytes: 0
mounts:
  - id: files
    name: Disposable files
    local_path: /mnt/files
    mode: read_write
    published: true
    enabled: true
transfer_grants: []
""")
    try:
        docker("network", "create", network)
        network_created = True
        common = ["--detach", "--network", network, "--security-opt", "no-new-privileges:true",
                  "--cap-drop", "ALL"]
        for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"):
            common += ["--cap-add", capability]
        node_name, control_name = network + "-node", network + "-control"
        node_token, password = secrets.token_hex(32), secrets.token_hex(24)
        docker("run", *common, "--name", node_name, "--network-alias", "node-smoke",
               "--publish", "127.0.0.1::8080", "--volume", "/mnt/files",
               "--env", "JOLT_OWNED_PATHS=/mnt/files",
               "--mount", "type=bind,src=" + str(config_path) + ",dst=/etc/jolt/node.yaml,readonly", "--env", "CONTROL_TOWER_TOKEN=" + node_token,
               "--env", "JOLT_STATE_ENCRYPTION_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode(), args.node_image)
        names.append(node_name)
        docker("run", *common, "--name", control_name, "--publish", "127.0.0.1::8090",
               "--env", "CONTROL_TOWER_ADMIN_PASSWORD=" + password,
               "--env", "CONTROL_TOWER_DB_ENCRYPTION_KEY=" + secrets.token_hex(32), args.control_image)
        names.append(control_name)
        node_base = "http://" + docker("port", node_name, "8080/tcp").splitlines()[0]
        control_base = "http://" + docker("port", control_name, "8090/tcp").splitlines()[0]
        exercise(node_base, control_base, node_name, node_token, password, args.expected_version)
    except Exception:
        for name in names:
            print(docker("logs", "--tail", "25", name).replace(node_token, "[redacted]").replace(password, "[redacted]"))
        raise
    finally:
        for name in reversed(names):
            docker("rm", "--force", "--volumes", name)
        if network_created:
            docker("network", "rm", network)
        configuration.cleanup()


if __name__ == "__main__":
    main()
