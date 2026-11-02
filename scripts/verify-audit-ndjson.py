#!/usr/bin/env python3
"""Verify a Jolt audit export against a separately retained checkpoint."""

import argparse
import hashlib
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="NDJSON export, or - for stdin")
    parser.add_argument("--previous-hash", required=True, help="Trusted hash preceding the first exported event")
    parser.add_argument("--after-id", type=int, default=0, help="Event ID of the trusted checkpoint")
    args = parser.parse_args()
    previous = args.previous_hash.lower()
    if len(previous) != 64 or any(c not in "0123456789abcdef" for c in previous):
        parser.error("--previous-hash must be a SHA-256 hex digest")
    stream = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
    last_id, count = args.after_id, 0
    try:
        for line in stream:
            event = json.loads(line)
            payload = event.get("chain_data", "")
            fields = json.loads(payload)
            if not isinstance(fields, list) or len(fields) != 15 or fields[0] != "jolt-audit-v1":
                raise ValueError("invalid chain data")
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            event_id = int(fields[2])
            if fields[1] != previous or digest != event.get("chain_hash") or event_id != event.get("event_id") or event_id <= last_id:
                raise ValueError("hash, predecessor, or event ID mismatch")
            expected = [event.get("actor_id", ""), event.get("actor_type", ""), event.get("action", ""), event.get("resource", ""), event.get("result", ""), event.get("correlation_id", ""), event.get("created_at", "")]
            if fields[3:10] != expected or json.loads(fields[10]) != event.get("policy_ids") or fields[11] != event.get("evaluated_path", "") or fields[12] != event.get("capability", "") or fields[13] != event.get("source_ip", "") or (json.loads(fields[14]) or {}) != (event.get("detail") or {}):
                raise ValueError("event content does not match chain data")
            previous, last_id, count = digest, event_id, count + 1
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Audit verification failed after event {last_id}: {exc}", file=sys.stderr)
        return 1
    finally:
        if stream is not sys.stdin:
            stream.close()
    print(f"Verified {count} events; last ID {last_id}; last hash {previous}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
