#!/usr/bin/env python3

"""Adds a marketplace instance to an already generated SCION topology.

The script is idempotent: running it again for the same IA reports what is
already in place instead of adding a second marketplace.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# <ISD>-<AS>, with the AS either as a hex triple (underscores or colons, the
# form used by gen/AS<as_id>) or as a plain decimal (BGP-style) AS number.
IA_RE = re.compile(
    r"^(?P<isd>\d{1,5})-"
    r"(?P<as>[0-9a-fA-F]{1,4}[_:][0-9a-fA-F]{1,4}[_:][0-9a-fA-F]{1,4}|\d{1,10})$"
)

MAX_ISD = (1 << 16) - 1
MAX_BGP_AS = (1 << 32) - 1

MARKETPLACE_TOML = """[general]
id = "marketplace"
config_dir = "gen/{as_dir}"

[log.console]
level = "debug"

[marketplace]
api_addr = "localhost:8888"
scion_api_addr = "localhost:8888"
currency = "CHF"
currency_exponent = 2
supports_redemption_delegation = true
delegation_hourly_fee = 10000
transaction_fee_relative = 0.01
transaction_fee_absolute = 10
split_combine_fee_absolute = 10

[marketplace_db]
connection = "gen-cache/marketplace.db"
"""

MARKETPLACE_PROGRAM = """[program:marketplace]
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

# The [program:marketplace] section, i.e. up to the next section or EOF.
PROGRAM_SECTION_RE = re.compile(
    r"^\[program:marketplace\]\s*$.*?(?=^\[|\Z)",
    re.MULTILINE | re.DOTALL,
)
PROGRAM_CONFIG_RE = re.compile(r"^command\s*=.*?gen/(?P<as_dir>[^/\s]+)/marketplace\.toml",
                               re.MULTILINE)


class SetupError(Exception):
    """An error that aborts the setup with a message, but without a traceback."""


def parseIA(ia_string: str):
    """Splits an IA into (isd, as_id), with the AS id in the gen/ underscore form."""
    match = IA_RE.match(ia_string.strip())
    if match is None:
        raise SetupError(
            f"invalid ISD-AS {ia_string!r}; expected e.g. 1-ff00_0_111, "
            "1-ff00:0:111 or 1-64512"
        )
    isd = int(match.group("isd"))
    if isd < 1 or isd > MAX_ISD:
        raise SetupError(f"invalid ISD in {ia_string!r}: must be in [1, {MAX_ISD}]")
    as_id = match.group("as")
    if as_id.isdigit() and int(as_id) > MAX_BGP_AS:
        raise SetupError(f"invalid AS number in {ia_string!r}: must be <= {MAX_BGP_AS}")
    return isd, as_id.replace(":", "_")


def marketplaceEntries(ia_colons: str):
    """The staticInfoConfig entries advertising this marketplace."""
    return [
        {
            "name": "Test Market",
            "protocol": "connectrpc/TLS/QUIC/SCION",
            "api": f"[{ia_colons},127.0.0.1]:9888",
            "website": "https://127.0.0.1:8889",
        },
        {
            "name": "Test Market",
            "protocol": "connectrpc/TLS/TCP",
            "api": "https://127.0.0.1:8888",
            "website": "https://127.0.0.1:8889",
        },
    ]


def loadStaticInfo(path: Path):
    """Reads staticInfoConfig.json and its embedded note object.

    Returns (static_info, note), both dicts. Missing files yield empty ones.
    """
    if not path.exists():
        return {}, {}

    try:
        static_info = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SetupError(f"cannot read {path}: {e}")
    if not isinstance(static_info, dict):
        raise SetupError(f"{path}: expected a JSON object, got {type(static_info).__name__}")

    note = static_info.get("note", "")
    if note == "":
        return static_info, {}
    try:
        note = json.loads(note)
    except (TypeError, json.JSONDecodeError):
        raise SetupError(
            f"{path}: the 'note' field is not a JSON object; refusing to overwrite it"
        )
    if not isinstance(note, dict):
        raise SetupError(
            f"{path}: the 'note' field is not a JSON object; refusing to overwrite it"
        )
    return static_info, note


def mergeEntries(existing, entries):
    """Merges the marketplace entries into the existing ones, keyed by name+protocol."""
    merged = [e for e in existing if isinstance(e, dict)]
    changed = len(merged) != len(existing)
    for entry in entries:
        key = (entry["name"], entry["protocol"])
        for i, old in enumerate(merged):
            if (old.get("name"), old.get("protocol")) == key:
                if old != entry:
                    merged[i] = entry
                    changed = True
                break
        else:
            merged.append(entry)
            changed = True
    return merged, changed


def addToGroup(text: str, group_name: str):
    """Adds the marketplace program to the [group:as<isd>-<as_id>] section."""
    pattern = re.compile(
        rf"(\[group:{re.escape(group_name)}\]\nprograms\s*=\s*)([^\n]+)",
        re.MULTILINE,
    )

    match = pattern.search(text)
    if match is None:
        groups = re.findall(r"^\[group:(.+)\]$", text, re.MULTILINE)
        known = ", ".join(groups) if groups else "none"
        raise SetupError(
            f"no [group:{group_name}] section in the supervisord config "
            f"(known groups: {known})"
        )

    programs = [p.strip() for p in match.group(2).split(",") if p.strip()]
    if "marketplace" in programs:
        return text, False

    programs.append("marketplace")
    return text[:match.start()] + match.group(1) + ",".join(programs) + text[match.end():], True


def main(args) -> None:
    isd, as_id = parseIA(args.ia)
    ia_colons = f"{isd}-{as_id.replace('_', ':')}"
    as_dir = f"AS{as_id}"            # e.g. ASff00_0_111
    group_name = f"as{isd}-{as_id}"  # e.g. as1-ff00_0_111

    # Paths
    gen_dir = Path(args.gen_dir)
    marketplace_dir = gen_dir / as_dir
    certs_dir = marketplace_dir / "certs"
    marketplace_toml = marketplace_dir / "marketplace.toml"
    static_info_json = marketplace_dir / "staticInfoConfig.json"
    supervisord_conf = gen_dir / "supervisord.conf"

    # 0. Validate the topology before touching anything, so that a typo in the
    # IA does not leave a half configured AS behind.
    if not gen_dir.is_dir():
        raise SetupError(f"{gen_dir} does not exist; generate the topology first")
    if not marketplace_dir.is_dir():
        raise SetupError(f"{marketplace_dir} does not exist; {ia_colons} is not part of {gen_dir}")
    if not supervisord_conf.is_file():
        raise SetupError(f"{supervisord_conf} does not exist; generate the topology first")

    try:
        supervisord_config = supervisord_conf.read_text(encoding="utf-8")
    except OSError as e:
        raise SetupError(f"cannot read {supervisord_conf}: {e}")

    # There is a single [program:marketplace]: if it exists, it must be ours.
    section = PROGRAM_SECTION_RE.search(supervisord_config)
    if section is not None:
        config = PROGRAM_CONFIG_RE.search(section.group(0))
        if config is None:
            raise SetupError(
                f"{supervisord_conf} already has a [program:marketplace] section with an "
                "unrecognized command; remove it before running this script"
            )
        if config.group("as_dir") != as_dir:
            raise SetupError(
                f"{supervisord_conf} already runs a marketplace for "
                f"{config.group('as_dir')}; only one marketplace is supported"
            )

    # 5. Append marketplace to [group:as<isd>-<as_id>]. Resolved here, before any
    # change is applied, so that a missing group is not a partial setup.
    supervisord_config, group_added = addToGroup(supervisord_config, group_name)

    static_info, note = loadStaticInfo(static_info_json)
    hummingbird = note.get("hummingbird", [])
    if not isinstance(hummingbird, list):
        raise SetupError(
            f"{static_info_json}: 'note'.hummingbird is not a list; refusing to overwrite it"
        )

    changes = []
    toml_content = MARKETPLACE_TOML.format(as_dir=as_dir)

    # 1 & 2. Create directories
    certs_dir.mkdir(parents=True, exist_ok=True)

    # 3. Write marketplace.toml, keeping any local edits to an existing one.
    if not marketplace_toml.exists():
        marketplace_toml.write_text(toml_content, encoding="utf-8")
        changes.append(f"wrote {marketplace_toml}")
    elif marketplace_toml.read_text(encoding="utf-8") != toml_content:
        print(f"{marketplace_toml} exists and differs from the default, left unchanged")

    # 4. Prepend the marketplace block
    if section is None:
        supervisord_config = MARKETPLACE_PROGRAM.format(as_dir=as_dir) + supervisord_config
        changes.append(f"added [program:marketplace] to {supervisord_conf}")

    if group_added:
        changes.append(f"added marketplace to [group:{group_name}]")

    if section is None or group_added:
        try:
            supervisord_conf.write_text(supervisord_config, encoding="utf-8")
        except OSError as e:
            raise SetupError(f"cannot write {supervisord_conf}: {e}")

    # 6. Advertise the marketplace in staticInfoConfig.json, without dropping
    # whatever else is already configured there.
    hummingbird, changed = mergeEntries(hummingbird, marketplaceEntries(ia_colons))
    if changed:
        note["hummingbird"] = hummingbird
        static_info["note"] = json.dumps(note)
        try:
            static_info_json.write_text(json.dumps(static_info, indent=2), encoding="utf-8")
        except OSError as e:
            raise SetupError(f"cannot write {static_info_json}: {e}")
        changes.append(f"advertised the marketplace in {static_info_json}")

    if not changes:
        print(f"Marketplace already configured for {ia_colons}, nothing to do")
        return
    for change in changes:
        print(change)
    print(f"Marketplace config added for {ia_colons}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Adds a marketplace to a generated SCION topology."
    )
    parser.add_argument(
        "ia",
        metavar="IA",
        help="ISD-AS hosting the marketplace, e.g. 1-ff00_0_111 or 1-ff00:0:111"
    )
    parser.add_argument(
        "--gen-dir",
        default="gen",
        help="Path to the generated topology directory (default: gen)."
    )

    try:
        main(parser.parse_args())
    except SetupError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
