// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

const (
	SchemaVersion = 1
	Schema        = `
	CREATE TABLE Assets(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		owner_id INTEGER,
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		bandwidth INTEGER NOT NULL,
		bandwidth_min INTEGER NOT NULL,
		bandwidth_max INTEGER NOT NULL,
		price INTEGER NOT NULL,
		time_granularity INTEGER NOT NULL,
		time_min_duration INTEGER NOT NULL,
		starts_at TEXT NOT NULL,
		stops_at TEXT NOT NULL,
		ingress INTEGER,
		egress INTEGER,
		state INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY (owner_id) REFERENCES Users(id)
	);
	CREATE INDEX idx_asset_owner ON Assets(owner_id);
	CREATE INDEX idx_asset_validity ON Assets(starts_at, stops_at);
	CREATE INDEX idx_assets_ia_validity_start ON Assets(isd_id, as_id, starts_at, stops_at);
	CREATE INDEX idx_assets_ia_validity_end ON Assets(isd_id, as_id, stops_at, starts_at);
	CREATE TABLE Reservations(
		id INTEGER NOT NULL,
		owner_id INTEGER NOT NULL,
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		ingress INTEGER NOT NULL,
		egress INTEGER NOT NULL,
		bandwidth INTEGER NOT NULL,
		starts_at TEXT NOT NULL,
		stops_at TEXT NOT NULL,
		key BLOB NOT NULL,
		FOREIGN KEY (owner_id) REFERENCES Users(id)
	);
	CREATE INDEX idx_reservations_owner ON Reservations(owner_id);
	CREATE INDEX idx_reservations_used ON Reservations(isd_id, as_id, starts_at, stops_at);
	CREATE TABLE Users(
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		pw_hash TEXT NOT NULL,
		jwt_version INTEGER NOT NULL DEFAULT 0,
		balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0)
	);
	CREATE INDEX idx_users_name ON Users(name);
	CREATE TABLE Ases(
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		jwt_version INTEGER NOT NULL DEFAULT 0,
		balance INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY(isd_id, as_id)
	);
	CREATE TABLE Redemption_Delegations(
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		res_id_limit INTEGER NOT NULL,
		expiration TEXT NOT NULL,
		key BLOB NOT NULL,
		encodings BLOB NOT NULL,
		PRIMARY KEY(isd_id, as_id)
	);
	CREATE INDEX idx_redemption_expiration ON Redemption_Delegations(expiration);
	`
)
