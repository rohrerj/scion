#!/usr/bin/env python3
from pathlib import Path
import re
import sys
import json


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python3 setup_marketplace.py <IA>")
        print("Example: python3 setup_marketplace.py 1-ff00_0_111")
        sys.exit(1)

    ia_id = sys.argv[1]              # e.g. ff00_0_111
    as_id = ia_id.split("-")[1]
    as_dir = f"AS{as_id}"            # e.g. ASff00_0_111
    group_name = f"as1-{as_id}"      # e.g. as1-ff00_0_111

    # Paths
    gen_dir = Path("gen")
    marketplace_dir = gen_dir / as_dir
    certs_dir = marketplace_dir / "certs"
    marketplace_toml = marketplace_dir / "marketplace.toml"
    static_info_json = marketplace_dir / "staticInfoConfig.json"
    supervisord_conf = gen_dir / "supervisord.conf"

    # 1 & 2. Create directories
    certs_dir.mkdir(parents=True, exist_ok=True)

    # 3. Write marketplace.toml
    marketplace_toml.write_text(
        f"""[general]
id = "marketplace"
config_dir = "gen/{as_dir}"

[log.console]
level = "debug"

[marketplace]
api_addr = "localhost:8888"
scion_api_addr = "localhost:9888"
currency = "CHF"
currency_exponent = 2
supports_redemption_delegation = true
delegation_hourly_fee = 10000
transaction_fee_relative = 0.01
transaction_fee_absolute = 10
split_combine_fee_absolute = 10

[marketplace_db]
connection = "gen-cache/marketplace.db"
""",
        encoding="utf-8",
    )

    # 4. Prepend marketplace block
    marketplace_block = f"""[program:marketplace]
autostart = false
autorestart = false
environment = TZ=UTC,GODEBUG="cgocheck=0"
stdout_logfile = logs/marketplace.log
redirect_stderr = True
startretries = 0
startsecs = 5
priority = 100
command = bin/marketplace --config gen/{as_dir}/marketplace.toml

"""

    if supervisord_conf.exists():
        text = supervisord_conf.read_text(encoding="utf-8")
    else:
        text = ""

    if "[program:marketplace]" not in text:
        text = marketplace_block + text

    # 5. Append marketplace to [group:as1-<AS_ID>]
    pattern = re.compile(
        rf"(\[group:{re.escape(group_name)}\]\nprograms\s*=\s*)([^\n]+)",
        re.MULTILINE,
    )

    def add_marketplace(match: re.Match) -> str:
        prefix = match.group(1)
        programs = [p.strip() for p in match.group(2).split(",")]

        if "marketplace" not in programs:
            programs.append("marketplace")

        return prefix + ",".join(programs)

    text = pattern.sub(add_marketplace, text, count=1)

    supervisord_conf.write_text(text, encoding="utf-8")

    # Build inner JSON object
    ia_id_colons = ia_id.replace("_",":")
    note_payload = {
        "hummingbird": [
            {
                "name": "Test Market",
                "protocol": "connectrpc/TLS/QUIC/SCION",
                "api": f"[{ia_id_colons},127.0.0.1]:9888",
                "website": "https://127.0.0.1:8889"
            },
            {
                "name": "Test Market",
                "protocol": "connectrpc/TLS/TCP",
                "api": "https://127.0.0.1:8888",
                "website": "https://127.0.0.1:8889"
            }
        ]
    }

    # Outer object: note contains JSON string
    static_info_payload = {
        "note": json.dumps(note_payload)
    }

    # Write file
    static_info_json.write_text(
        json.dumps(static_info_payload, indent=2),
        encoding="utf-8",
    )

    print(f"Marketplace config added for {ia_id}")

if __name__ == "__main__":
    main()