#!/usr/bin/env python3
"""Start a development node; preserve its editable YAML on subsequent runs."""
import argparse
import base64
import json
import os
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("name")
parser.add_argument("--api", type=int, required=True)
parser.add_argument("--mtls", type=int, required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
root = repo / "node" / "testdata" / args.name
root.mkdir(parents=True, exist_ok=True)
(root / "files").mkdir(exist_ok=True)
configuration = root / "node.yaml"
if not configuration.exists():
    quote = json.dumps
    configuration.write_text(f'''version: 1
node_name: {quote(args.name)}
api_address: "127.0.0.1:{args.api}"
mtls_address: "127.0.0.1:{args.mtls}"
mtls_public_endpoint: "https://127.0.0.1:{args.mtls}"
data_dir: {quote(str(root / "state"))}
keys_dir: {quote(str(root / "keys"))}
mounts:
  - id: files
    name: Files
    local_path: {quote(str(root / "files"))}
    mode: read_write
    published: true
    enabled: true
transfer_grants: []
''')
environment = os.environ.copy()
environment.setdefault("CONTROL_TOWER_TOKEN", f"development-{args.name}-token")
# A public fixture key is intentionally restricted to the development launcher.
environment.setdefault("JOLT_STATE_ENCRYPTION_KEY", base64.b64encode(bytes(range(32))).decode())
environment["CGO_ENABLED"] = "0"
os.chdir(repo / "node")
os.execvpe("go", ["go", "run", "./backend/cmd/jolt-node", "--config", str(configuration)], environment)
