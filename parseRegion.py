import base64
import json
import re
import urllib.parse
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

OUTPUT_FILE = "output.txt"


# ISO 3166-1 alpha-2 country / territory codes.
# XX is intentionally NOT included because it is our fallback.
VALID_ISO_CODES = {
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR",
    "AS", "AT", "AU", "AW", "AX", "AZ",

    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL",
    "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY",
    "BZ",

    "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM",
    "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ",

    "DE", "DJ", "DK", "DM", "DO", "DZ",

    "EC", "EE", "EG", "EH", "ER", "ES", "ET",

    "FI", "FJ", "FK", "FM", "FO", "FR",

    "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM",
    "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY",

    "HK", "HM", "HN", "HR", "HT", "HU",

    "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",

    "JE", "JM", "JO", "JP",

    "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY",
    "KZ",

    "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV",
    "LY",

    "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM",
    "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
    "MX", "MY", "MZ",

    "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR",
    "NU", "NZ",

    "OM",

    "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR",
    "PS", "PT", "PW", "PY",

    "QA",

    "RE", "RO", "RS", "RU", "RW",

    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK",
    "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY",
    "SZ",

    "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN",
    "TO", "TR", "TT", "TV", "TW", "TZ",

    "UA", "UG", "UM", "US", "UY", "UZ",

    "VA", "VC", "VE", "VG", "VI", "VN", "VU",

    "WF", "WS",

    "YE", "YT",

    "ZA", "ZM", "ZW",
}


# ============================================================
# Flag handling
# ============================================================

REGIONAL_A = ord("🇦")


def country_code_to_flag(code):
    """
    Convert an ISO alpha-2 code into regional-indicator symbols.

    DE -> 🇩🇪
    SC -> 🇸🇨
    XX -> 🇽🇽
    """
    code = code.upper()

    if not re.fullmatch(r"[A-Z]{2}", code):
        return "🇽🇽"

    return "".join(
        chr(REGIONAL_A + ord(char) - ord("A"))
        for char in code
    )


def flag_to_country_code(flag):
    """
    Convert two regional-indicator symbols into their
    corresponding two-letter code.

    🇩🇪 -> DE
    🇸🇨 -> SC

    Returns None if it isn't two regional indicators.
    """
    if len(flag) != 2:
        return None

    codes = []

    for char in flag:
        value = ord(char)

        if not (ord("🇦") <= value <= ord("🇿")):
            return None

        codes.append(chr(ord("A") + value - ord("🇦")))

    return "".join(codes)


def find_valid_flag(text):
    """
    Search text for a regional-indicator pair.

    Returns the first VALID country flag found.

    Invalid pairs such as 🇽🇽 are ignored.
    """
    regional = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

    for match in regional.finditer(text):
        flag = match.group(0)
        code = flag_to_country_code(flag)

        if code in VALID_ISO_CODES:
            return flag

    return None


def get_flag_from_remark(remark):
    """
    Return a valid flag from the remark.

    If there is no valid country flag, return 🇽🇽.
    """
    flag = find_valid_flag(remark)

    if flag is None:
        return country_code_to_flag("XX")

    return flag


# ============================================================
# Base64
# ============================================================

def decode_base64(data):
    """
    Decode normal or URL-safe Base64.

    Handles missing padding.
    """
    data = data.strip()

    data = data.replace("-", "+")
    data = data.replace("_", "/")

    data += "=" * (-len(data) % 4)

    return base64.b64decode(data)


def encode_base64(data):
    return base64.b64encode(data).decode("ascii")


# ============================================================
# VLESS / Trojan / SS
# ============================================================

def sanitize_url_fragment(link, number, scheme):
    """
    Sanitize links where the remark is stored in the URL fragment.

    Examples:
        vless://...#remark
        trojan://...#remark
        ss://...#remark
    """
    parts = urllib.parse.urlsplit(link)

    original_remark = urllib.parse.unquote(parts.fragment)

    flag = get_flag_from_remark(original_remark)

    new_remark = f"{flag} #{number}"

    encoded_remark = urllib.parse.quote(
        new_remark,
        safe=""
    )

    return urllib.parse.urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        parts.query,
        encoded_remark
    ))


# ============================================================
# VMess
# ============================================================

def sanitize_vmess(link, number):
    """
    VMess links contain Base64-encoded JSON.

    The remark is stored in the JSON 'ps' property.
    """
    encoded = link[len("vmess://"):].strip()

    try:
        decoded = decode_base64(encoded)
        config = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        print(f"[WARNING] Could not decode VMess link: {exc}")
        return link

    original_remark = str(config.get("ps", ""))

    flag = get_flag_from_remark(original_remark)

    config["ps"] = f"{flag} #{number}"

    new_json = json.dumps(
        config,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    return "vmess://" + encode_base64(new_json)


# ============================================================
# Link sanitization
# ============================================================

def sanitize_link(link, counters):
    """
    Sanitize a single supported share link.

    Numbering is maintained independently for each flag.
    """

    link = link.strip()

    if not link:
        return None

    # Remove accidental surrounding whitespace.
    link = link.strip()

    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", link)

    if not scheme_match:
        return None

    scheme = scheme_match.group(1).lower()

    # --------------------------------------------------------
    # VMess
    # --------------------------------------------------------

    if scheme == "vmess":
        # We need the original remark first so we know which
        # counter to increment.

        encoded = link[len("vmess://"):].strip()

        try:
            decoded = decode_base64(encoded)
            config = json.loads(decoded.decode("utf-8"))
            original_remark = str(config.get("ps", ""))
        except Exception as exc:
            print(f"[WARNING] Invalid VMess link: {exc}")
            return link

        flag = get_flag_from_remark(original_remark)

        counters[flag] = counters.get(flag, 0) + 1
        number = counters[flag]

        config["ps"] = f"{flag} #{number}"

        new_json = json.dumps(
            config,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")

        return "vmess://" + encode_base64(new_json)

    # --------------------------------------------------------
    # VLESS / Trojan / Shadowsocks
    # --------------------------------------------------------

    if scheme in ("vless", "trojan", "ss"):
        parts = urllib.parse.urlsplit(link)

        original_remark = urllib.parse.unquote(parts.fragment)

        flag = get_flag_from_remark(original_remark)

        counters[flag] = counters.get(flag, 0) + 1
        number = counters[flag]

        new_remark = f"{flag} #{number}"

        encoded_remark = urllib.parse.quote(
            new_remark,
            safe=""
        )

        return urllib.parse.urlunsplit((
            parts.scheme,
            parts.netloc,
            parts.path,
            parts.query,
            encoded_remark
        ))

    # --------------------------------------------------------
    # Unsupported protocol
    # --------------------------------------------------------

    print(f"[WARNING] Unsupported protocol: {scheme}://")
    return None


# ============================================================
# Extract share links from pasted text
# ============================================================

SUPPORTED_SCHEMES = (
    "vmess",
    "vless",
    "trojan",
    "ss",
)


def extract_links(text):
    """
    Extract supported share links from an arbitrary pasted block.

    This means you can paste a whole chunk of text rather than
    having to carefully format one link per line.
    """

    pattern = re.compile(
        r"(?i)(?:"
        + "|".join(re.escape(s) for s in SUPPORTED_SCHEMES)
        + r")://[^\s]+"
    )

    links = []

    for match in pattern.finditer(text):
        link = match.group(0)

        # Remove common trailing punctuation that might have
        # been copied along with the URL.
        link = link.rstrip(".,;)]}>\"'")

        links.append(link)

    return links


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 70)
    print("V2Ray / Xray Share Link Sanitizer")
    print("=" * 70)
    print()
    print("Paste your share links below.")
    print("You can paste multiple lines or a larger block of text.")
    print("Press ENTER twice (empty line) when finished.")
    print()

    lines = []

    while True:
        try:
            line = input()
        except EOFError:
            break

        if not line.strip():
            break

        lines.append(line)

    if not lines:
        print("\nNo input provided.")
        input("\nPress Enter to close...")
        return

    pasted_text = "\n".join(lines)

    links = extract_links(pasted_text)

    if not links:
        print("\nNo supported share links found.")
        print("Supported: vmess://, vless://, trojan://, ss://")
        input("\nPress Enter to close...")
        return

    print(f"\nFound {len(links)} link(s).")
    print("Processing...\n")

    counters = {}
    sanitized = []

    for link in links:
        result = sanitize_link(link, counters)

        if result is not None:
            sanitized.append(result)

    # --------------------------------------------------------
    # Write output file
    # --------------------------------------------------------

    output_path = Path(__file__).resolve().parent / OUTPUT_FILE

    output_path.write_text(
        "\n".join(sanitized) + "\n",
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print("=" * 70)
    print("SANITIZED LINKS")
    print("=" * 70)

    for link in sanitized:
        print(link)

    print("=" * 70)

    print()
    print(f"Processed: {len(sanitized)} link(s)")
    print(f"Output:    {output_path}")

    print()
    print("Numbering:")
    for flag, count in counters.items():
        print(f"  {flag}: {count}")

    print()
    input("Press Enter to close...")


if __name__ == "__main__":
    main()