"""Check forbidden dispatch variants and normal greetings in the patched lab."""

import json
from pathlib import Path
import requests

base = "http://127.0.0.1:7861"
config = requests.get(base + "/config", timeout=20).json()
component = next(c["id"] for c in config["components"] if c["type"] == "textbox")
results = []
for method in ["move_resource_to_block_cache", "preprocess", "postprocess",
               "__getattribute__", "not_a_method"]:
    response = requests.post(base + "/component_server", json={
        "component_id": component, "data": "/etc/passwd",
        "fn_name": method, "session_hash": "lab1regression",
    }, timeout=20)
    assert response.status_code == 404
    results.append({"check": method, "status": response.status_code,
                    "body": response.json()})
for name in ["Cheng Yang", "", "Security Lab"]:
    response = requests.post(base + "/api/predict", json={
        "data": [name], "fn_index": 0,
    }, timeout=20)
    assert response.status_code == 200
    assert response.json()["data"][0] == f"Hello {name}!"
    results.append({"check": "greet " + repr(name), "status": response.status_code,
                    "output": response.json()["data"][0]})
destination = Path(__file__).resolve().parents[1] / "evidence/cve-after/regression.json"
destination.write_text(json.dumps(results, indent=2))
for result in results:
    print(result)
print("All 8 regression checks passed.")
