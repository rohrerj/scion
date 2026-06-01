#!/usr/bin/env python3
from pathlib import Path
import re
import sys


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python3 setup_marketplace.py <AS_ID>")
        print("Example: python3 setup_marketplace.py ff00_0_111")
        sys.exit(1)

    as_id = sys.argv[1]              # e.g. ff00_0_111
    as_dir = f"AS{as_id}"            # e.g. ASff00_0_111
    group_name = f"as1-{as_id}"      # e.g. as1-ff00_0_111

    # Paths
    gen_dir = Path("gen")
    marketplace_dir = gen_dir / as_dir
    certs_dir = marketplace_dir / "certs"
    marketplace_toml = marketplace_dir / "marketplace.toml"
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
account_addr = "localhost:8889"
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

    print(f"Marketplace config added for {as_id}")


if __name__ == "__main__":
    main()