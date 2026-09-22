#!/usr/bin/env python3

import base64
import json
import ssl
import urllib.request
from Crypto.Cipher import AES


# ============================================================
# SETTINGS
# ============================================================

FIREBASE_SOURCES = [
    (
        "vostok-rtdb",
        "https://vostok-vpn-default-rtdb.europe-west1.firebasedatabase.app/.json",
    ),
    (
        "nooken-rtdb",
        "https://nooken-vpn.europe-west1.firebasedatabase.app/.json",
    ),
]

ENCRYPTED_SOURCES = [
    (
        "vostok-encrypted",
        "https://asannov.github.io/nooken/config_vostok.json",
    ),
    (
        "nooken-encrypted",
        "https://asannov.github.io/nooken/config.json",
    ),
]


KEY = bytes.fromhex(
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)


OUTPUT_FILE = "vostok_links.txt"
COMBINED_JSON = "vostok_all.json"


# ============================================================
# SSL / HTTP
# ============================================================

CTX = ssl.create_default_context()


def get(url, headers=None):
    headers = headers or {}

    req = urllib.request.Request(
        url,
        headers=headers
    )

    with urllib.request.urlopen(
        req,
        context=CTX,
        timeout=30
    ) as r:
        return r.read()


# ============================================================
# GLOBAL DEDUP
# ============================================================

seen = set()
links = []

source_stats = {}


def add_link(uri, source):
    uri = (uri or "").strip()

    if not uri:
        return

    if uri in seen:
        return

    seen.add(uri)
    links.append(uri)

    source_stats[source] = source_stats.get(source, 0) + 1


# ============================================================
# FIREBASE
# ============================================================

def process_firebase(name, url):

    print()
    print("=" * 80)
    print(f"FIREBASE: {name}")
    print("=" * 80)

    raw = get(
        url,
        {
            "Accept": "application/json",
        }
    )

    data = json.loads(raw.decode("utf-8"))

    if not isinstance(data, dict):
        print("ERROR: Firebase response is not an object")
        return

    countries = 0
    configs = 0

    for country, node in data.items():

        if not isinstance(node, dict):
            continue

        countries += 1

        premium = node.get("premium")
        published = node.get("published")
        title = node.get("title")

        config_list = node.get("configs") or []

        print(
            f"{country}: "
            f"premium={premium} "
            f"published={published} "
            f"{title} "
            f"configs={len(config_list)}"
        )

        for c in config_list:

            if not isinstance(c, dict):
                continue

            uri = c.get("config") or ""

            if uri:
                configs += 1
                add_link(uri, name)

    print()
    print(f"Countries: {countries}")
    print(f"Configs found: {configs}")


# ============================================================
# ENCRYPTED GITHUB PAGES
# ============================================================

def process_encrypted(name, url):

    print()
    print("=" * 80)
    print(f"ENCRYPTED: {name}")
    print("=" * 80)

    raw = get(
        url,
        {
            "User-Agent": "okhttp",
        }
    )

    blob = raw.decode("utf-8").strip()

    parts = blob.split(":")

    if len(parts) != 3:
        raise ValueError(
            f"{name}: expected nonce:tag:ciphertext"
        )

    nonce_b64, tag_b64, ct_b64 = parts

    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ct_b64)

    print(f"Nonce:      {len(nonce)} bytes")
    print(f"Tag:        {len(tag)} bytes")
    print(f"Ciphertext: {len(ciphertext)} bytes")

    cipher = AES.new(
        KEY,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    data = json.loads(plaintext)

    if not isinstance(data, dict):
        raise ValueError(
            f"{name}: decrypted JSON is not an object"
        )

    print(
        "Countries:",
        ", ".join(data.keys())
    )

    configs = 0

    for country, node in data.items():

        if not isinstance(node, dict):
            continue

        config_list = node.get("configs") or []

        print(
            f"{country}: "
            f"premium={node.get('premium')} "
            f"configs={len(config_list)}"
        )

        for c in config_list:

            if not isinstance(c, dict):
                continue

            uri = c.get("config") or ""

            if uri:
                configs += 1
                add_link(uri, name)

    print()
    print(f"Configs found: {configs}")


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("VOSTOK / NOOKEN CONFIG COLLECTOR")
    print("=" * 80)

    # --------------------------------------------------------
    # Firebase sources
    # --------------------------------------------------------

    for name, url in FIREBASE_SOURCES:
        try:
            process_firebase(name, url)

        except Exception as e:
            print()
            print(f"ERROR [{name}]: {e}")

    # --------------------------------------------------------
    # Encrypted sources
    # --------------------------------------------------------

    for name, url in ENCRYPTED_SOURCES:
        try:
            process_encrypted(name, url)

        except Exception as e:
            print()
            print(f"ERROR [{name}]: {e}")

    # --------------------------------------------------------
    # Save links
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        if links:
            f.write("\n".join(links))
            f.write("\n")

    # --------------------------------------------------------
    # Save combined JSON with source statistics
    # --------------------------------------------------------

    combined = {
        "total_unique": len(links),
        "sources": source_stats,
        "configs": links,
    }

    with open(
        COMBINED_JSON,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            combined,
            f,
            ensure_ascii=False,
            indent=2
        )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("RESULT")
    print("=" * 80)

    for source in (
        [x[0] for x in FIREBASE_SOURCES]
        + [x[0] for x in ENCRYPTED_SOURCES]
    ):
        print(
            f"{source}: "
            f"{source_stats.get(source, 0)} unique"
        )

    print()
    print(f"TOTAL UNIQUE: {len(links)}")

    # --------------------------------------------------------
    # Gist
    # --------------------------------------------------------

    update_gist()

    print()
    print("DONE")


# ============================================================
# GIST
# ============================================================

def update_gist():

    import os
    import json
    import urllib.request

    gist_token = os.environ.get("GIST_TOKEN")
    gist_id = os.environ.get("GIST_ID")

    if not gist_token:
        print("GIST_TOKEN not set - Gist update skipped")
        return

    if not gist_id:
        print("GIST_ID not set - Gist update skipped")
        return

    try:
        with open(
            OUTPUT_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            content = f.read()

        payload = json.dumps({
            "files": {
                "vostok_links.txt": {
                    "content": content
                }
            }
        }).encode("utf-8")

        req = urllib.request.Request(
            f"https://api.github.com/gists/{gist_id}",
            data=payload,
            method="PATCH",
            headers={
                "Authorization": f"Bearer {gist_token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "vostok-fetcher",
            }
        )

        with urllib.request.urlopen(
            req,
            timeout=30
        ) as r:

            status = r.status
            response = r.read().decode(
                "utf-8",
                errors="replace"
            )

        print()
        print(
            f"Gist update: HTTP {status}"
        )

        if status == 200:
            print("Gist updated successfully")
        else:
            print(response[:1000])

    except Exception as e:

        print()
        print(f"GIST ERROR: {e}")


if __name__ == "__main__":
    main()
