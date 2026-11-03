import { createPublicKey, generateKeyPairSync, type JsonWebKey, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import {
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  SERVICE_CREDENTIAL_ISSUER,
} from "@uichat-mira/cloud-auth-contracts";
import type { ServiceCredentialKeyMaterialConfig } from "../../src/service-credentials/keyring.js";
import type { ServiceCredentialVerifierConfig } from "../../src/service-credentials/index.js";
import { createFirstPartySession, createTestOAuthContext, type TestOAuthContext } from "./oauth.js";

export type TestServiceCredentialContext = TestOAuthContext;

export const TEST_ACCOUNT_PASSWORD = "correct horse battery staple";

const isolatedDirectories: string[] = [];

/** A throwaway SQLite database + app instance, removed by `disposeIsolatedContexts`. */
export function createIsolatedServiceCredentialContext(
  prefix = "mira-guanlan-credential-",
): TestServiceCredentialContext {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  isolatedDirectories.push(dir);
  return createTestServiceCredentialContext(join(dir, "auth.sqlite"));
}

export function disposeIsolatedServiceCredentialContexts(): void {
  for (const dir of isolatedDirectories.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Provisions the account and returns a first-party device-bound Cloud Session. */
export async function provisionedSession(
  context: TestServiceCredentialContext,
  username = "alice",
) {
  await context.service.provisionAccount(username, TEST_ACCOUNT_PASSWORD);
  return createFirstPartySession(context, { username, password: TEST_ACCOUNT_PASSWORD });
}

export async function issueServiceCredential(
  context: TestServiceCredentialContext,
  token: string,
  body: unknown,
) {
  return context.app.inject({
    method: "POST",
    url: "/v1/service-credentials",
    headers: { authorization: `Bearer ${token}` },
    payload: body as Record<string, unknown>,
  });
}

/** Public keys the issuer advertises, shaped for offline verification. */
export function trustedServiceCredentialKeys(
  context: TestServiceCredentialContext,
): Map<string, KeyObject> {
  const ring = context.keyRing;
  if (!ring) throw new Error("Expected a configured key ring");
  return new Map(
    ring.jwks.keys.map((jwk) => [
      jwk.kid,
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
    ]),
  );
}

export function guanlanVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_GUANLAN_AUDIENCE,
    publicKeys: trustedServiceCredentialKeys(context),
  };
}

export function shiyanVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_SHIYAN_AUDIENCE,
    publicKeys: trustedServiceCredentialKeys(context),
  };
}

export function relayVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
    publicKeys: trustedServiceCredentialKeys(context),
    expectedRelay: { room: "room-7f3a", role: "client" },
  };
}

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
