#!/usr/bin/env python3

import json
import sqlite3
import hashlib
import bcrypt
import argparse
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

"""
Example JSON file:
{
    "version": "4abdd9041b766012ed2b58222505e0a8aeead3208b7dab513bc338eacb6eb11f",
    "users": [
        {
            "name": "Alice",
            "password": "1234"
        }
    ],
    "accounts": [
        {
            "user": "Alice",
            "balance": 1000000000
        },
        {
            "user": "Alice",
            "scope": "bandwidth-tester",
            "balance": 100000
        }
    ],
    "ases": [
        {
            "ia": "1-ff00:0:110"
        }
    ],
    "assets": [
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "ingress": 1
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "ingress": 2
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "egress": 1
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "egress": 2
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "ingress": 1,
            "egress": 0
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "ingress": 2,
            "egress": 0
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "ingress": 0,
            "egress": 1
        },
        {
            "ia": "1-ff00:0:110",
            "bandwidth": 1000,
            "bandwidth_min": 10,
            "bandwidth_max": 1000,
            "price": 1,
            "time_granularity": 5,
            "time_min_duration": 5,
            "starts_at": "2026-01-01T00:00:00Z",
            "stops_at": "2027-01-01T00:00:00Z",
            "ingress": 0,
            "egress": 2
        }
    ],
    "reservations": [
        {
            "id": 1,
            "ia": "1-ff00:0:110",
            "owner": "Alice",
            "ingress": 1,
            "egress": 2,
            "bandwidth": 100,
            "bw_encoded": 20,
            "starts_at": "2026-08-01T00:00:00Z",
            "stops_at": "2026-08-02T00:00:00Z",
            "key": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
        }
    ],
    "delegations": [
        {
            "ia": "1-ff00:0:110",
            "res_id_limit": 100000,
            "expiration": "2027-01-01T00:00:00Z",
            "paid_until": "2027-01-01T00:00:00Z",
            "key": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
            "encodings": [
                10, 20, 30, 40, 50, 60, 70, 80, 90, 100
            ]
        }
    ]
}
"""

DEFAULT_PASSWORD = "1234"
DEFAULT_USERS = ["alice", "bob"]
DEFAULT_USER_BALANCE = 1000000
DEFAULT_AS_BALANCE = 0
DEFAULT_ASSET_BANDWIDTH = 1000000
DEFAULT_ASSET_BANDWIDTH_MIN = 10
DEFAULT_ASSET_BANDWIDTH_MAX = 1000000
DEFAULT_ASSET_PRICE = 1
DEFAULT_ASSET_TIME_GRANULARITY = 10
DEFAULT_ASSET_TIME_MIN_DURATION = 10
DEFAULT_ASSET_DURATION = timedelta(days=100)

def loadJson(path):
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)
    return data

def loadTopology(genDir):
    """Reads the IA and interface IDs of every AS of a generated topology."""
    topologies = sorted(Path(genDir).glob("AS*/topology.json"))
    if not topologies:
        raise FileNotFoundError(f"no AS*/topology.json found in {genDir}")
    ases = []
    for path in topologies:
        topo = loadJson(path)
        ia = topo.get("isd_as")
        if ia is None:
            raise ValueError(f"{path} has no isd_as")
        ifids = sorted(
            int(ifid)
            for router in topo.get("border_routers", {}).values()
            for ifid in router.get("interfaces", {})
        )
        ases.append((ia, ifids))
    return ases

def interfacePairs(ifids):
    """The (ingress, egress) pairs of an AS.

    Interface 0 stands for no interface, i.e. a flyover that starts or ends in
    this AS, so that ASes with a single interface get assets as well.
    """
    pairs = [(i, e) for i in ifids for e in ifids if i != e]
    pairs += [(0, e) for e in ifids]
    pairs += [(i, 0) for i in ifids]
    return pairs

def defaultEntries(genDir, now=None):
    """Builds the default users, ASes and assets for the topology in genDir."""
    if now is None:
        now = datetime.now(timezone.utc)
    startsAt = now.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    stopsAt = (now + DEFAULT_ASSET_DURATION).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    ases = loadTopology(genDir)
    assets = [
        {
            "ia": ia,
            "bandwidth": DEFAULT_ASSET_BANDWIDTH,
            "bandwidth_min": DEFAULT_ASSET_BANDWIDTH_MIN,
            "bandwidth_max": DEFAULT_ASSET_BANDWIDTH_MAX,
            "price": DEFAULT_ASSET_PRICE,
            "time_granularity": DEFAULT_ASSET_TIME_GRANULARITY,
            "time_min_duration": DEFAULT_ASSET_TIME_MIN_DURATION,
            "starts_at": startsAt,
            "stops_at": stopsAt,
            "ingress": ingress,
            "egress": egress,
        }
        for ia, ifids in ases
        for ingress, egress in interfacePairs(ifids)
    ]
    return {
        "users": [
            {"name": name, "password": DEFAULT_PASSWORD}
            for name in DEFAULT_USERS
        ],
        "accounts": [
            {"user": name, "balance": DEFAULT_USER_BALANCE}
            for name in DEFAULT_USERS
        ],
        "ases": [
            {"ia": ia, "password": DEFAULT_PASSWORD, "balance": DEFAULT_AS_BALANCE}
            for ia, _ in ases
        ],
        "assets": assets,
    }

def removeExisting(db, data):
    """Drops the entries that the database already contains.

    The default entries can this way be applied repeatedly without duplicating
    rows, and without resetting the balances of what is already there.
    """
    users = {name for (name,) in db.execute("SELECT name FROM Users")}
    accounts = set(db.execute(
        "SELECT u.name, a.scope FROM Accounts a JOIN Users u ON u.id = a.user_id"
    ))
    ases = set(db.execute("SELECT isd_id, as_id FROM Ases"))
    assets = set(db.execute("SELECT isd_id, as_id, ingress, egress FROM Assets"))

    remaining = dict(data)
    remaining["users"] = [
        u for u in data.get("users", [])
        if u.get("name") not in users
    ]
    remaining["accounts"] = [
        a for a in data.get("accounts", [])
        if (a.get("user"), a.get("scope")) not in accounts
    ]
    remaining["ases"] = [
        a for a in data.get("ases", [])
        if parseIA(a.get("ia")) not in ases
    ]
    remaining["assets"] = [
        a for a in data.get("assets", [])
        if parseIA(a.get("ia")) + (a.get("ingress"), a.get("egress")) not in assets
    ]
    return remaining

def insertAll(db, data) -> bool:
    if not insertUsers(db, data.get("users")):
        return False
    if not insertAccounts(db, data.get("accounts")):
        return False
    if not insertASes(db, data.get("ases")):
        return False
    if not insertAssets(db, data.get("assets")):
        return False
    if not insertReservations(db, data.get("reservations")):
        return False
    return insertDelegations(db, data.get("delegations"))

def hash_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        sql = f.read()
    normalized = re.sub(r"\s+", " ", sql).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

def verifyScheme(schemePath, version):
    actualVersion = hash_file(schemePath)
    if version != actualVersion:
        print("scheme version mismatch. Expected: ", actualVersion)
        return False
    return True

def hash_password(password: str) -> str:
    if password is None:
        return None
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    )
    return hashed.decode("utf-8")

def insertAccounts(db, accounts) -> bool:
    if accounts is None:
        return True
    db.executemany(
        """
        INSERT OR REPLACE INTO Accounts (scope, balance, user_id)
        VALUES (?, ?, (
            SELECT id
            FROM Users
            WHERE name = ?
            LIMIT 1
        ))
        """,
        [
            (u.get("scope"), u.get("balance"), u.get("user"))
            for u in accounts
        ],
    )
    return True

def insertUsers(db,users) -> bool:
    if users is None:
        return True
    for u in users:
        u["pw_hash"] = hash_password(u.get("password"))
    db.executemany(
        """
        INSERT OR REPLACE INTO Users (name, pw_hash)
        VALUES (?, ?)
        """,
        [
            (u.get("name"), u.get("pw_hash"))
            for u in users
        ],
    )
    return True

def parseIA(ia_string):
    parts = ia_string.split("-")
    isd_id = int(parts[0])
    as_string = parts[1]
    as_parts = as_string.split(":")
    if len(as_parts) == 1:
        return isd_id, int(as_string)
    if len(as_parts) != 3:
        print("invalid IA", ia_string)
        return 0,0
    as_id = 0
    for i in range(3):
        as_id <<= 16
        as_id |= int(as_parts[i], 16)
    return isd_id, as_id

def insertAssets(db, assets) -> bool:
    if assets is None:
        return True
    for a in assets:
        isd_id, as_id = parseIA(a.get("ia"))
        if isd_id == 0 and as_id == 0:
            return False
        a["isd_id"] = isd_id
        a["as_id"] = as_id
    db.executemany(
        """
        INSERT INTO Assets (isd_id, as_id, bandwidth, bandwidth_min, bandwidth_max, price, time_granularity, time_min_duration, starts_at, stops_at, ingress, egress, account_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (
            SELECT a.id
            FROM Accounts a
            JOIN Users u ON u.ID = a.user_id
            WHERE u.name = ? AND a.scope IS NULL
            LIMIT 1
        ))
        """,
        [
            (u.get("isd_id"), u.get("as_id"), u.get("bandwidth"), u.get("bandwidth_min"), u.get("bandwidth_max"), u.get("price"), u.get("time_granularity"), u.get("time_min_duration"), u.get("starts_at"), u.get("stops_at"), u.get("ingress"), u.get("egress"), u.get("owner"),)
            for u in assets
        ],
    )
    return True

def insertASes(db, ases) -> bool:
    if ases is None:
        return True
    for a in ases:
        isd_id, as_id = parseIA(a.get("ia"))
        if isd_id == 0 and as_id == 0:
            return False
        a["isd_id"] = isd_id
        a["as_id"] = as_id
        a["pw_hash"] = hash_password(a.get("password"))
        if a.get("pw_hash") == None:
            a["pw_hash"] = ""
        if a.get("jwt_version") == None:
            a["jwt_version"] = 0
        if a.get("balance") == None:
            a["balance"] = 0
    db.executemany(
        """
        INSERT OR REPLACE INTO Ases (isd_id, as_id, pw_hash, jwt_version, balance)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (u.get("isd_id"), u.get("as_id"), u.get("pw_hash"), u.get("jwt_version"), u.get("balance"))
            for u in ases
        ],
    )
    return True

def insertReservations(db, reservations):
    if reservations is None:
        return True
    for a in reservations:
        isd_id, as_id = parseIA(a.get("ia"))
        if isd_id == 0 and as_id == 0:
            return False
        a["isd_id"] = isd_id
        a["as_id"] = as_id
        a["key_bytes"] = bytes.fromhex(a.get("key"))
    for u in reservations:
        db.execute(
            """
        INSERT OR REPLACE INTO Reservations (reservation_id, isd_id, as_id, ingress, egress, bandwidth, bw_encoded, starts_at, stops_at, key, account_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (
            SELECT id
            FROM Users
            WHERE name = ?
            LIMIT 1
        ))
        """, (u.get("id") , u.get("isd_id"), u.get("as_id"), u.get("ingress"), u.get("egress"), u.get("bandwidth"), u.get("bw_encoded"), u.get("starts_at"), u.get("stops_at"), u.get("key_bytes"),u.get("owner"))
        )
    return True

def insertDelegations(db, delegations):
    if delegations is None:
        return True
    for a in delegations:
        isd_id, as_id = parseIA(a.get("ia"))
        if isd_id == 0 and as_id == 0:
            return False
        a["isd_id"] = isd_id
        a["as_id"] = as_id
        a["key_bytes"] = bytes.fromhex(a.get("key"))
        a["encoding_bytes"] = b"".join(
            i.to_bytes(4, byteorder="little")
            for i in a.get("encodings")
        )
    db.executemany(
        """
        INSERT OR REPLACE INTO Redemption_Delegations (isd_id, as_id, res_id_limit, expiration, paid_until, key, encodings)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (u.get("isd_id"), u.get("as_id"), u.get("res_id_limit"), u.get("expiration"), u.get("paid_until"), u.get("key_bytes"),u.get("encoding_bytes"))
            for u in delegations
        ],
    )
    return True

def applyScheme(db, schemePath):
    with open(schemePath, "r", encoding="utf-8") as f:
        db.executescript(f.read())

def main(args):
    data = {}
    if args.file is not None:
        data = loadJson(args.file)
        if not verifyScheme(args.schema, data.get("version")):
            return
    if args.default_entries:
        try:
            data = defaultEntries(args.gen_dir)
        except (OSError, ValueError) as e:
            print("cannot read the topology:", e)
            return
    conn = sqlite3.connect(args.db)
    cursor = conn.cursor()
    try:
        applyScheme(cursor, args.schema)
        if args.default_entries:
            data = removeExisting(cursor, data)
            added = {section: len(e) for section, e in data.items() if e}
            if not added:
                print("the default entries are already in the database")
                return
            print("adding " + ", ".join(f"{n} {section}" for section, n in added.items()))
        if insertAll(cursor, data):
            conn.commit()
            print("stored in database")
        else:
            conn.rollback()
            print("changes rolled back")
    except Exception as e:
        print("error", e)
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Loads assets, users, reservations and delegations into marketplace db")
    parser.add_argument(
        "--db",
        default="gen-cache/marketplace.db",
        help="Path to the SQLite database."
    )
    parser.add_argument(
        "--schema",
        default="marketplace/db/schema.sql",
        help="Path to the schema.sql file."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--file",
        help="Path to the JSON file to import."
    )
    source.add_argument(
        "--default-entries",
        action="store_true",
        help="Add the default users, ASes and assets for the topology in --gen-dir. "
             "Entries that are already in the database are left untouched."
    )
    parser.add_argument(
        "--gen-dir",
        default="gen",
        help="Path to the generated topology, read by --default-entries (default: gen)."
    )

    args = parser.parse_args()
    main(args)