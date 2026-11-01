-- GLN-012: transactional delivery intent. Cloud Auth never stores Guanlan business data.
CREATE TABLE guanlan_registration_outbox (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivering','delivered','withheld')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_attempt_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  lease_until TEXT,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX guanlan_registration_due ON guanlan_registration_outbox(status, next_attempt_at);
