import json
import subprocess


def az(*args: str) -> dict | list:
    cmd = ["az", *args, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "az command failed").strip())
    if not result.stdout.strip():
        return []
    return json.loads(result.stdout)
