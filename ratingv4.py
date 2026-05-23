import re
import sys
import base64
import json
from urllib.parse import unquote, quote

# Adjust these to change score range / sensitivity
SCALING = 120      # increases overall scores
EXP = 0.6          # lower = less latency influence (0.5-0.8 typical)

def vpn_score(down_mbps, latency_ms):
    """Score = scaling * down / (latency ^ exp). Higher down & lower latency -> higher score."""
    if latency_ms <= 0:
        return 0
    # Use float for exponent; protect against very small latency
    latency_pow = latency_ms ** EXP
    score = SCALING * down_mbps / latency_pow
    return round(score)

# Pattern: optional old score, then digits↓, then digitsms (no jitter)
pattern = re.compile(r'(?:^(\d+)\s+)?.*?(\d+)↓.*?(\d+)ms')

def decode_vmess(url):
    try:
        encoded = url.split("vmess://", 1)[1]
        padded = encoded + '=' * (-len(encoded) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
        return json.loads(decoded)
    except:
        return None

def process_line(url):
    url = url.strip()

    if url.startswith("vmess://"):
        data = decode_vmess(url)
        if not data or "ps" not in data:
            return url
        decoded = data["ps"]
        vmess_data = data
    else:
        if '#' not in url:
            return url
        base_part, name = url.split('#', 1)
        decoded = unquote(name)
        vmess_data = None

    match = pattern.search(decoded)
    if not match:
        return url

    _, down_str, latency_str = match.groups()
    try:
        down = int(down_str)
        latency = int(latency_str)
    except:
        return url

    score = vpn_score(down, latency)

    # Remove old score if present, then prepend new score
    cleaned = re.sub(r'^\d+\s+', '', decoded)
    new_name = f"{score} {cleaned}"

    if vmess_data:
        vmess_data["ps"] = new_name
        new_json = json.dumps(vmess_data, separators=(',', ':'))
        new_encoded = base64.b64encode(new_json.encode()).decode()
        return f"vmess://{new_encoded}"
    else:
        encoded_name = quote(new_name)
        return f"{base_part}#{encoded_name}"

print("Paste your v2ray configs")
print("Make sure you're on a newline, press Ctrl+Z (Windows), and then Enter.")
input_text = sys.stdin.read()
lines = input_text.splitlines()

results = [process_line(line) for line in lines if line.strip()]

print("\n----- Result -----")
for line in results:
    print(line)

input("\nPress Enter to exit...")