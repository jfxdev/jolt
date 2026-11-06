#!/usr/bin/env python3
"""Revoke, rotate and replace roots with real nodes and a real Control Tower.

Build both binaries first and pass their paths with --node-bin and --control-bin.
Requires OpenSSL. Everything lives in a temporary directory, on loopback.

It takes a few minutes because the Control Tower looks at its nodes once a
minute and the steps wait for that. What it shows, with real TLS between real
processes:

  - a node set to managed-only is reached by the Control Tower's certificate
    alone, and reports that it authenticates that way;
  - revoking a node's certificate stops the Control Tower from reaching it
    while the other node keeps working and learns of the revocation;
  - a leaked intermediate is revoked, and the node's certificate is replaced
    under the new one without the node being enrolled again;
  - a root rotation: the new root is published, promoted once the node holds
    it, the node moves to the new chain, and the old root leaves by itself.
"""

import argparse
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True  # importing the sibling script must leave nothing in the repository
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("managed_tls_smoke", here / "managed-tls-smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

CT = "/api/v1/control-tower/"


def node_by_name(control, name):
    for entry in control.json("GET", CT + "nodes")["items"]:
        if entry["name"] == name:
            return entry["node_id"]
    raise RuntimeError("no node named " + name)


def inventory_node(control, node_id):
    for entry in control.json("GET", CT + "crypto/ca")["nodes"]:
        if entry["node_id"] == node_id:
            return entry
    raise RuntimeError("node not in the inventory")


def reaches(control, node_id):
    return control.call("GET", f"/api/v1/nodes/{node_id}/mounts")[0] == 200


def diagnose(root, control, *node_ids):
    """What a person would look at when a step does not happen: the node rows and the logs."""
    print("--- inventory", file=sys.stderr)
    try:
        for node_id in node_ids:
            print(inventory_node(control, node_id), file=sys.stderr)
    except Exception as error:  # noqa: BLE001 - diagnostics must never hide the failure
        print("inventory unavailable:", error, file=sys.stderr)
    for name in ("control", "stable", "doomed"):
        lines = smoke.read_log(root / (name + ".log")).splitlines()[-12:]
        print(f"--- {name}.log", file=sys.stderr)
        print("\n".join(lines), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-bin", required=True)
    parser.add_argument("--control-bin", required=True)
    args = parser.parse_args()
    processes = []
    try:
        with tempfile.TemporaryDirectory(prefix="jolt-rotation-smoke-") as temp:
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
    port = smoke.freeport()
    control_url = f"https://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CONTROL_TOWER_", "JOLT_"))}
    env.update({
        "CONTROL_TOWER_TLS_MODE": "managed", "CONTROL_TOWER_ADDRESS": f"127.0.0.1:{port}", "CONTROL_TOWER_CA_ADDRESS": "off",
        "CONTROL_TOWER_PUBLIC_BASE_URL": control_url, "CONTROL_TOWER_DATA_DIR": str(root / "control"),
        "CONTROL_TOWER_ADMIN_PASSWORD": "smoke-admin-password", "CONTROL_TOWER_DB_ENCRYPTION_KEY": "smoke-encryption-key-that-is-long-enough-1234",
        "CONTROL_TOWER_STATIC_DIR": str(root),
    })
    smoke.start([args.control_bin], env, root / "control.log", processes)
    insecure = smoke.Client(control_url)
    insecure.context = ssl._create_unverified_context()
    smoke.wait(lambda: insecure.call("GET", "/health")[0] == 200, "the Control Tower to start")
    status, root_pem, _ = insecure.call("GET", "/.well-known/jolt/ca.pem")
    (root / "root.pem").write_bytes(root_pem)
    control = smoke.Client(control_url, cafile=str(root / "root.pem"))
    status, _, headers = control.call("POST", CT + "auth/login", {"username": "admin", "password": "smoke-admin-password"})
    assert status == 200, status
    control.cookie = headers["Set-Cookie"].split(";")[0]

    def enroll(name, mode):
        token = control.json("POST", CT + "enrollments/tokens", {"node_name": name}, expect=201)["token"]
        api, mtls = smoke.freeport(), smoke.freeport()
        _, config = smoke.node_files(root, name, api, mtls)
        text = config.read_text().replace("tls_mode: managed", "tls_mode: " + mode)
        config.write_text(text)
        smoke.start([args.node_bin, "--config", str(config)], smoke.node_env(token), root / (name + ".log"), processes)
        smoke.wait(lambda: "enrolled" in smoke.read_log(root / (name + ".log")), name + " to enroll")
        node_id = node_by_name(control, name)
        smoke.wait(lambda: reaches(control, node_id), "the Control Tower to reach " + name)
        return node_id

    stable = enroll("stable", "managed-only")
    doomed = enroll("doomed", "managed")
    print("ok   two nodes enrolled, one set to managed-only; the Control Tower reaches both")

    # The nodes say how they authenticate the Control Tower once it has asked.
    smoke.wait(lambda: inventory_node(control, stable).get("auth_mode") == "certificate" and inventory_node(control, doomed).get("auth_mode") == "token",
               "the sync to record how each node authenticates", seconds=150)
    print("ok   the inventory shows managed-only by certificate and the other by token")

    # Revoking one node's certificate stops the Control Tower from reaching it only.
    control.json("POST", CT + "crypto/revocations", {"node_id": doomed, "reason": "smoke"})
    smoke.wait(lambda: not reaches(control, doomed), "the Control Tower to stop reaching the revoked node")
    assert reaches(control, stable), "revoking one node cut off another"
    revoked = control.json("GET", CT + "crypto/revocations")["items"]
    assert len(revoked) == 1 and revoked[0]["reason"] == "smoke", revoked
    smoke.wait(lambda: inventory_node(control, stable)["bundle_behind"] == 0, "the other node to learn of the revocation", seconds=150)
    print("ok   a revoked node is no longer reached, the other node keeps working and has the revocation")

    # A leaked intermediate: revoked at once, and the node moves to the new one by itself.
    before = inventory_node(control, stable)["cert_serial"]
    control.json("POST", CT + "crypto/ca/intermediate/rotate", {"revoke_previous": True, "reason": "smoke"})
    try:
        smoke.wait(lambda: inventory_node(control, stable)["cert_serial"] != before, "the node's certificate to be replaced", seconds=200)
    except RuntimeError:
        diagnose(root, control, stable)
        raise
    smoke.wait(lambda: reaches(control, stable), "the Control Tower to reach the node under the new intermediate")
    ca = control.json("GET", CT + "crypto/ca")
    assert sum(1 for item in ca["items"] if item["kind"] == "intermediate") == 1, "the revoked intermediate is still listed"
    print("ok   a leaked intermediate was revoked and the node's certificate was replaced without enrolling again")

    # Root rotation.
    original = control.json("GET", CT + "crypto/ca")["root_fingerprint"]
    control.json("POST", CT + "crypto/ca/root/rotate", expect=202)
    status, next_pem, _ = insecure.call("GET", "/.well-known/jolt/ca.pem")
    assert next_pem == root_pem, "the active root changed before it was promoted"
    smoke.wait(lambda: inventory_node(control, stable)["bundle_behind"] == 0, "the node to hold the bundle with both roots", seconds=150)
    bundle = control.json("GET", CT + "crypto/trust-bundle")
    assert len(bundle["roots"]) == 2, "the bundle does not carry both roots"
    control.json("POST", CT + "crypto/ca/root/promote", {})
    print("ok   the next root was published, the node confirmed it, and it was promoted")

    # The Control Tower now serves under the new root; people take it from the same place.
    status, new_pem, _ = insecure.call("GET", "/.well-known/jolt/ca.pem")
    assert new_pem != root_pem, "the published root did not change after the promotion"
    (root / "root2.pem").write_bytes(new_pem)
    control = smoke.Client(control_url, cafile=str(root / "root2.pem"))
    status, _, headers = control.call("POST", CT + "auth/login", {"username": "admin", "password": "smoke-admin-password"})
    assert status == 200, "the Control Tower is not reachable under the new root"
    control.cookie = headers["Set-Cookie"].split(";")[0]
    assert control.json("GET", CT + "crypto/ca")["root_fingerprint"] != original

    # The node moves to the new chain and the old root leaves the bundle by itself.
    def retired():
        ca = control.json("GET", CT + "crypto/ca")
        return ca["rotation"]["phase"] == "none" and len(control.json("GET", CT + "crypto/trust-bundle")["roots"]) == 1
    smoke.wait(retired, "the old root to leave the bundle", seconds=240)
    smoke.wait(lambda: reaches(control, stable), "the Control Tower to reach the node on the new chain")
    smoke.wait(lambda: inventory_node(control, stable)["bundle_behind"] == 0, "the node to hold the final bundle", seconds=150)
    print("ok   the node moved to the new chain, the old root left the bundle, and the Control Tower still reaches it")
    print("ok   done")


if __name__ == "__main__":
    main()
