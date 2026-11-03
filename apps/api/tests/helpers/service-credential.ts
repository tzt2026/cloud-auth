import { generateKeyPairSync } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { ServiceCredentialKeyMaterialConfig } from "../../src/service-credentials/keyring.js";
import { createTestOAuthContext, type TestOAuthContext } from "./oauth.js";

export type TestServiceCredentialContext = TestOAuthContext;

export function createTestServiceCredentialKeyMaterial(
  overrides: Partial<ServiceCredentialKeyMaterialConfig> = {},
): ServiceCredentialKeyMaterialConfig {
  const { privateKey } = generateKeyPairSync("ed25519");
  return {
    activeKeyId: "test-active-key",
    activePrivateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    retiringPublicKeys: [],
    ttlSeconds: 300,
    ...overrides,
  };
}

export function createTestServiceCredentialContext(
  databasePath: string,
  keyMaterial: ServiceCredentialKeyMaterialConfig | null = createTestServiceCredentialKeyMaterial(),
): TestServiceCredentialContext {
  return createTestOAuthContext(databasePath, {
    serviceCredentialKeyMaterial: keyMaterial,
  });
}

/**
 * GLN-012 durable registration outbox, copied from the merged migration
 * (`cloud-auth` `dev` `931ae6c`, `migrations/008_guanlan_registration_outbox.sql`).
 * Cloud Auth only reads this projection; it never stores Guanlan business data.
 */
const GUANLAN_REGISTRATION_OUTBOX_TABLE = "guanlan_registration_outbox";
const GUANLAN_REGISTRATION_OUTBOX_COLUMNS = `account_id TEXT PRIMARY KEY REFERENCES accounts(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivering','delivered','withheld','failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_attempt_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  lease_until TEXT,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP`;

export type GuanlanRegistrationStatus =
  | "pending"
  | "delivering"
  | "delivered"
  | "withheld"
  | "failed";

function outboxExists(db: DatabaseSync): boolean {
  const row = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(GUANLAN_REGISTRATION_OUTBOX_TABLE) as { name?: unknown } | undefined;
  return typeof row?.name === "string";
}

/**
 * Creates the GLN-012 projection table (if needed) and records one account's
 * registration status. This is a real SQLite table on the same connection the
 * issuance transaction uses; it is not an in-memory stub of the gate.
 */
export function setGuanlanRegistrationStatus(
  db: DatabaseSync,
  accountId: string,
  status: GuanlanRegistrationStatus,
): void {
  if (!outboxExists(db)) {
    db.exec(
      `CREATE TABLE ${GUANLAN_REGISTRATION_OUTBOX_TABLE} (${GUANLAN_REGISTRATION_OUTBOX_COLUMNS})`,
    );
    db.exec(
      `CREATE INDEX guanlan_registration_due ON ${GUANLAN_REGISTRATION_OUTBOX_TABLE}(status, next_attempt_at)`,
    );
  }
  db.prepare(
    `INSERT INTO ${GUANLAN_REGISTRATION_OUTBOX_TABLE} (account_id, status, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(account_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at`,
  ).run(accountId, status, new Date().toISOString());
}
