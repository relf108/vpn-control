"""Refresh public Mullvad source data before release, never runtime gateway state."""

# Standalone maintenance command, not a Python package.
# ruff: noqa: CPY001, INP001, T201

import argparse
import base64
import datetime as dt
import ipaddress
import json
import urllib.request
from pathlib import Path

URL = "https://api.mullvad.net/www/relays/all/"
KEY_BYTES = 32


def catalog(rows: list[dict], retrieved: str) -> dict:
    """Choose a deterministic active IPv4 WireGuard relay for every city/region."""
    groups = {}
    active = [row for row in rows if row["active"] and row["type"] == "wireguard"]
    for row in sorted(active, key=lambda item: item["hostname"]):
        ipaddress.IPv4Address(row["ipv4_addr_in"])
        if len(base64.b64decode(row["pubkey"], validate=True)) != KEY_BYTES:
            msg = "Invalid public relay key"
            raise ValueError(msg)
        region = "-".join(row["hostname"].split("-")[:2])
        groups.setdefault(
            region,
            {
                "label": f"{row['country_name']} / {row['city_name']} ({row['hostname']})",
                "publicKey": row["pubkey"],
                "endpoint": f"{row['ipv4_addr_in']}:51820",
            },
        )
    if not groups or "au-mel" not in groups:
        msg = "Missing region catalog or Melbourne relay"
        raise ValueError(msg)
    return {
        "source": URL,
        "retrieved": retrieved,
        "regionCount": len(groups),
        "activeWireGuardRelays": len(active),
        "regions": dict(sorted(groups.items())),
    }


def main() -> None:
    """Write public metadata without reading local profiles or account data."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("regions.json"))
    args = parser.parse_args()
    with urllib.request.urlopen(URL, timeout=30) as response:
        result = catalog(json.load(response), dt.datetime.now(dt.UTC).date().isoformat())
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"Wrote {result['regionCount']} active regions to {args.output}")


if __name__ == "__main__":
    main()
