import re
import os
import sys
import base64
import json
from urllib.parse import unquote, quote


def vpn_score(down, up, latency, jitter):
    stability = 1 + (jitter / latency)
    effective_latency = latency * stability
    return 100 * (down**0.6 * up**0.3) / (effective_latency**0.4)


pattern = re.compile(
    r'(?:^(\d+)\s+)? .*?(\d+)↓\s*(\d+)↑.*?\·\s*(\d+)\+(\d+)ms'
)


def decode_vmess(url):
    try:
        encoded = url.split("vmess://", 1)[1]
        padded = encoded + '=' * (-len(encoded) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
        data = json.loads(decoded)
        return data
    except:
        return None


def process_line(url):
    url = url.strip()

    # --- VMESS handling ---
    if url.startswith("vmess://"):
        data = decode_vmess(url)
        if not data or "ps" not in data:
            return url

        decoded = data["ps"]
        vmess_data = data

    else:
        if '#' not in url:
            return url

        base, name = url.split('#', 1)
        decoded = unquote(name)
        vmess_data = None

    # --- Parse stats ---
    match = pattern.search(decoded)
    if not match:
        return url

    _, down, up, latency, jitter = match.groups()
    down, up, latency, jitter = map(int, (down, up, latency, jitter))

    score = round(vpn_score(down, up, latency, jitter))

    # remove old score if present
    cleaned = re.sub(r'^\d+\s+', '', decoded)
    new_name = f"{score} {cleaned}"

    # --- rebuild ---
    if vmess_data:
        vmess_data["ps"] = new_name
        new_json = json.dumps(vmess_data, separators=(',', ':'))
        new_encoded = base64.b64encode(new_json.encode()).decode()
        return f"vmess://{new_encoded}"

    else:
        encoded_name = quote(new_name)
        return f"{base}#{encoded_name}"


print("Paste the configs you'd like to process, press Ctrl-Z, and then Enter:")

input_text = sys.stdin.read()
lines = input_text.splitlines()

results = [process_line(line) for line in lines if line.strip()]

print("\n----- Result -----")
for line in results:
    print(line)

input('\nPress Enter to exit...')