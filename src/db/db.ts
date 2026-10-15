import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type DB = Database.Database;

// Append-only. Each entry runs once, tracked via PRAGMA user_version.
const MIGRATIONS: string[] = [
  `
  CREATE TABLE block_events (
    id          INTEGER PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE,
    vlan_id     TEXT NOT NULL,
    client_ip   TEXT NOT NULL,
    client_name TEXT,
    domain      TEXT NOT NULL,
    url         TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
  );
  CREATE INDEX block_events_client ON block_events (client_ip, domain, created_at);

  CREATE TABLE requests (
    id             INTEGER PRIMARY KEY,
    block_event_id INTEGER NOT NULL REFERENCES block_events(id),
    vlan_id        TEXT NOT NULL,
    domain         TEXT NOT NULL,
    note           TEXT,
    status         TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    created_at     INTEGER NOT NULL,
    decided_by     TEXT,
    decided_at     INTEGER
  );
  CREATE INDEX requests_status ON requests (status, created_at);

  CREATE TABLE overrides (
    id             INTEGER PRIMARY KEY,
    scope          TEXT NOT NULL CHECK (scope IN ('global', 'vlan')),
    vlan_id        TEXT,
    kind           TEXT NOT NULL CHECK (kind IN ('allow', 'pause')),
    domain         TEXT,
    expires_at     INTEGER,
    created_by     TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    revoked_at     INTEGER,
    revoked_by     TEXT,
    block_event_id INTEGER REFERENCES block_events(id),
    request_id     INTEGER REFERENCES requests(id),
    CHECK ((scope = 'vlan') = (vlan_id IS NOT NULL)),
    CHECK ((kind = 'allow') = (domain IS NOT NULL))
  );
  CREATE INDEX overrides_active ON overrides (revoked_at, expires_at);

  -- Reconciler bookkeeping: which allowed[] entries it added to each Advanced Blocking group.
  CREATE TABLE managed_allowed (
    group_name TEXT NOT NULL,
    domain     TEXT NOT NULL,
    PRIMARY KEY (group_name, domain)
  );

  -- Reconciler bookkeeping: original values of settings it changed (e.g. enableBlocking before a pause).
  CREATE TABLE managed_flags (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE audit_log (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    details TEXT NOT NULL
  );
  `,
];

export function openDb(path: string): DB {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);
  return db;
}

function migrate(db: DB): void {
  const current = db.pragma("user_version", { simple: true }) as number;
  for (let v = current; v < MIGRATIONS.length; v++) {
    db.transaction(() => {
      db.exec(MIGRATIONS[v]!);
      db.pragma(`user_version = ${v + 1}`);
    })();
  }
}
