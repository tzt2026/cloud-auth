import { randomUUID } from "node:crypto";
import { enqueueGuanlanRegistration, withholdGuanlanRegistration, resumeGuanlanRegistration } from "../guanlan-registration.js";
import type { DatabaseSync } from "node:sqlite";
import type { DevicePlatform } from "@uichat-mira/cloud-auth-contracts";
import { verifySessionSecretHash } from "../security/session-token.js";

export interface AccountRecord {
  id: string;
  username: string;
  usernameNormalized: string;
  passwordHash: string;
  passwordVersion: number;
  isAllowed: boolean;
  disabledAt: string | null;
  createdAt: string;
  updatedAt: string;
  passwordChangedAt: string;
  lastLoginAt: string | null;
}

export interface SessionRecord {
  id: string;
  accountId: string;
  deviceId: string | null;
  deviceAccountId: string | null;
  deviceRevokedAt: string | null;
  secretHash: string;
  expiresAt: string;
  createdAt: string;
  lastSeenAt: string;
  rotatedAt: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
}

export interface SessionWithAccount {
  session: SessionRecord;
  account: AccountRecord;
}

type AccountRow = {
  id: string;
  username: string;
  username_normalized: string;
  password_hash: string;
  password_version: number;
  is_allowed: number;
  disabled_at: string | null;
  created_at: string;
  updated_at: string;
  password_changed_at: string;
  last_login_at: string | null;
};

type SessionAccountRow = AccountRow & {
  session_id: string;
  account_id: string;
  device_id: string | null;
  device_account_id: string | null;
  device_revoked_at: string | null;
  secret_hash: string;
  expires_at: string;
  session_created_at: string;
  last_seen_at: string;
  rotated_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
};

export interface SessionDeviceBinding {
  installationId: string;
  platform: "desktop" | "mobile";
}

export interface ServiceCredentialAuthority {
  accountId: string;
  deviceId: string;
  devicePlatform: DevicePlatform;
}

export type ServiceCredentialAuthorityFailure = "unauthorized" | "device_required";

export type ServiceCredentialAuthorityResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: ServiceCredentialAuthorityFailure };

type ServiceCredentialAuthorityRow = {
  account_id: string;
  device_id: string | null;
  secret_hash: string;
  expires_at: string;
  revoked_at: string | null;
  is_allowed: number;
  disabled_at: string | null;
  device_account_id: string | null;
  device_platform: DevicePlatform | null;
  device_revoked_at: string | null;
};

export class AuthRepository {
  constructor(private readonly db: DatabaseSync) {}

  findAccountByUsername(usernameNormalized: string): AccountRecord | null {
    const row = this.db
      .prepare(
        `SELECT id, username, username_normalized, password_hash, password_version, is_allowed, disabled_at,
                created_at, updated_at, password_changed_at, last_login_at
           FROM accounts
          WHERE username_normalized = ?`,
      )
      .get(usernameNormalized) as AccountRow | undefined;
    return row ? mapAccount(row) : null;
  }

  findAccountById(accountId: string): AccountRecord | null {
    const row = this.db
      .prepare(
        `SELECT id, username, username_normalized, password_hash, password_version, is_allowed, disabled_at,
                created_at, updated_at, password_changed_at, last_login_at
           FROM accounts
          WHERE id = ?`,
      )
      .get(accountId) as AccountRow | undefined;
    return row ? mapAccount(row) : null;
  }

  createAccount(username: string, usernameNormalized: string, passwordHash: string, now: string): AccountRecord {
    const id = randomUUID();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db.prepare(
        `INSERT INTO accounts (
           id, username, username_normalized, password_hash, is_allowed, disabled_at,
           created_at, updated_at, password_changed_at
         ) VALUES (?, ?, ?, ?, 1, NULL, ?, ?, ?)`,
      ).run(id, username, usernameNormalized, passwordHash, now, now, now);
      enqueueGuanlanRegistration(this.db, id, now);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }

    const account = this.findAccountById(id);
    if (!account) throw new Error("Account insert did not persist");
    return account;
  }

  updatePasswordAndRevokeSessions(
    accountId: string,
    passwordHash: string,
    now: string,
    revokeReason = "password_reset",
  ): void {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .prepare(
          "UPDATE accounts SET password_hash = ?, password_version = password_version + 1, password_changed_at = ?, updated_at = ? WHERE id = ?",
        )
        .run(passwordHash, now, now, accountId);
      this.revokeAllSessions(accountId, revokeReason, now);
      this.revokePendingOAuthAuthorizations(accountId, revokeReason, now);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  changePasswordIfSessionActive(
    accountId: string,
    sessionId: string,
    expectedSecretHash: string,
    expectedPasswordVersion: number,
    passwordHash: string,
    now: string,
  ): boolean {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      // Verify the initiating session at the mutation boundary, after Argon2's async work.
      const result = this.db
        .prepare(
          `UPDATE accounts
              SET password_hash = ?,
                  password_version = password_version + 1,
                  password_changed_at = ?,
                  updated_at = ?
            WHERE id = ?
              AND is_allowed = 1
              AND disabled_at IS NULL
              AND password_version = ?
              AND EXISTS (
                SELECT 1
                  FROM sessions s
                  LEFT JOIN devices d ON d.id = s.device_id
                 WHERE s.id = ?
                   AND s.account_id = accounts.id
                   AND s.secret_hash = ?
                   AND s.revoked_at IS NULL
                   AND s.expires_at > ?
                   AND (
                     s.device_id IS NULL
                     OR (d.account_id = s.account_id AND d.revoked_at IS NULL)
                   )
              )`,
        )
        .run(passwordHash, now, now, accountId, expectedPasswordVersion, sessionId, expectedSecretHash, now);

      if (result.changes !== 1) {
        this.db.exec("ROLLBACK;");
        return false;
      }
      this.revokeAllSessions(accountId, "password_changed", now);
      this.revokePendingOAuthAuthorizations(accountId, "password_changed", now);
      this.db.exec("COMMIT;");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  /**
   * Re-verifies the complete account/device/session authority inside one
   * BEGIN IMMEDIATE transaction. The action runs while the write lock is held,
   * so a concurrent logout, rotate, device revoke, or account disable cannot
   * interleave between the final authority check and credential signing.
   *
   * Legacy `device_id IS NULL` Web sessions are valid for normal login/restore
   * but cannot obtain service credentials.
   */
  issueWithinActiveDeviceSession<T>(
    sessionId: string,
    expectedSecretHash: string,
    now: string,
    action: (authority: ServiceCredentialAuthority) => T,
  ): ServiceCredentialAuthorityResult<T> {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const row = this.db
        .prepare(
          `SELECT
             s.account_id, s.device_id, s.secret_hash, s.expires_at, s.revoked_at,
             a.is_allowed, a.disabled_at,
             d.account_id AS device_account_id, d.platform AS device_platform,
             d.revoked_at AS device_revoked_at
           FROM sessions s
           JOIN accounts a ON a.id = s.account_id
           LEFT JOIN devices d ON d.id = s.device_id
           WHERE s.id = ?`,
        )
        .get(sessionId) as ServiceCredentialAuthorityRow | undefined;

      const expiresAt = row ? Date.parse(row.expires_at) : Number.NaN;
      if (
        !row ||
        !Number.isFinite(expiresAt) ||
        expiresAt <= Date.parse(now) ||
        !verifySessionSecretHash(row.secret_hash, expectedSecretHash) ||
        row.revoked_at !== null ||
        row.is_allowed !== 1 ||
        row.disabled_at !== null
      ) {
        this.db.exec("ROLLBACK;");
        return { ok: false, reason: "unauthorized" };
      }

      if (row.device_id === null) {
        this.db.exec("ROLLBACK;");
        return { ok: false, reason: "device_required" };
      }

      if (
        row.device_account_id !== row.account_id ||
        row.device_platform === null ||
        row.device_revoked_at !== null
      ) {
        this.db.exec("ROLLBACK;");
        return { ok: false, reason: "unauthorized" };
      }

      const value = action({
        accountId: row.account_id,
        deviceId: row.device_id,
        devicePlatform: row.device_platform,
      });
      this.db.exec("COMMIT;");
      return { ok: true, value };
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  setAllowedAndRevokeIfDenied(accountId: string, allowed: boolean, now: string): void {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .prepare("UPDATE accounts SET is_allowed = ?, updated_at = ? WHERE id = ?")
        .run(allowed ? 1 : 0, now, accountId);
      if (!allowed) {
        this.revokeAllSessions(accountId, "admission_revoked", now);
        withholdGuanlanRegistration(this.db, accountId, now);
      } else {
        resumeGuanlanRegistration(this.db, accountId, now);
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  setDisabledAndRevoke(accountId: string, disabled: boolean, now: string): void {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .prepare("UPDATE accounts SET disabled_at = ?, updated_at = ? WHERE id = ?")
        .run(disabled ? now : null, now, accountId);
      if (disabled) {
        this.revokeAllSessions(accountId, "account_disabled", now);
        withholdGuanlanRegistration(this.db, accountId, now);
      } else {
        resumeGuanlanRegistration(this.db, accountId, now);
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  createSessionIfAccountActive(
    id: string,
    accountId: string,
    expectedPasswordVersion: number,
    secretHash: string,
    expiresAt: string,
    now: string,
    device?: SessionDeviceBinding,
  ): boolean {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const result = device
        ? this.db
            .prepare(
              `INSERT INTO sessions (
                 id, account_id, device_id, secret_hash, expires_at,
                 created_at, last_seen_at, rotated_at, revoked_at, revoke_reason
               )
               SELECT ?, a.id, d.id, ?, ?, ?, ?, NULL, NULL, NULL
                 FROM accounts a
                 JOIN devices d ON d.account_id = a.id
                WHERE a.id = ?
                  AND a.is_allowed = 1
                  AND a.disabled_at IS NULL
                  AND a.password_version = ?
                  AND d.installation_id = ?
                  AND d.platform = ?
                  AND d.revoked_at IS NULL`,
            )
            .run(
              id,
              secretHash,
              expiresAt,
              now,
              now,
              accountId,
              expectedPasswordVersion,
              device.installationId,
              device.platform,
            )
        : this.db
            .prepare(
              `INSERT INTO sessions (
                 id, account_id, device_id, secret_hash, expires_at,
                 created_at, last_seen_at, rotated_at, revoked_at, revoke_reason
               )
               SELECT ?, id, NULL, ?, ?, ?, ?, NULL, NULL, NULL
                 FROM accounts
                WHERE id = ?
                  AND is_allowed = 1
                  AND disabled_at IS NULL
                  AND password_version = ?`,
            )
            .run(id, secretHash, expiresAt, now, now, accountId, expectedPasswordVersion);

      if (result.changes !== 1) {
        this.db.exec("ROLLBACK;");
        return false;
      }

      this.db
        .prepare("UPDATE accounts SET last_login_at = ?, updated_at = ? WHERE id = ?")
        .run(now, now, accountId);
      this.db.exec("COMMIT;");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  findSessionWithAccount(sessionId: string): SessionWithAccount | null {
    const row = this.db
      .prepare(
        `SELECT
           s.id AS session_id, s.account_id, s.device_id, s.secret_hash, s.expires_at,
           s.created_at AS session_created_at, s.last_seen_at, s.rotated_at, s.revoked_at, s.revoke_reason,
           d.account_id AS device_account_id, d.revoked_at AS device_revoked_at,
           a.id, a.username, a.username_normalized, a.password_hash, a.password_version, a.is_allowed, a.disabled_at,
           a.created_at, a.updated_at, a.password_changed_at, a.last_login_at
         FROM sessions s
         JOIN accounts a ON a.id = s.account_id
         LEFT JOIN devices d ON d.id = s.device_id
         WHERE s.id = ?`,
      )
      .get(sessionId) as SessionAccountRow | undefined;

    if (!row) return null;
    return {
      session: {
        id: row.session_id,
        accountId: row.account_id,
        deviceId: row.device_id,
        deviceAccountId: row.device_account_id,
        deviceRevokedAt: row.device_revoked_at,
        secretHash: row.secret_hash,
        expiresAt: row.expires_at,
        createdAt: row.session_created_at,
        lastSeenAt: row.last_seen_at,
        rotatedAt: row.rotated_at,
        revokedAt: row.revoked_at,
        revokeReason: row.revoke_reason,
      },
      account: mapAccount(row),
    };
  }

  touchSession(sessionId: string, now: string): boolean {
    const result = this.db
      .prepare(
        `UPDATE sessions
            SET last_seen_at = ?
          WHERE id = ?
            AND revoked_at IS NULL
            AND expires_at > ?
            AND (
              device_id IS NULL
              OR EXISTS (
                SELECT 1
                  FROM devices d
                 WHERE d.id = sessions.device_id
                   AND d.account_id = sessions.account_id
                   AND d.revoked_at IS NULL
              )
            )`,
      )
      .run(now, sessionId, now);
    if (result.changes !== 1) return false;

    this.db
      .prepare(
        `UPDATE devices
            SET last_seen_at = ?
          WHERE id = (SELECT device_id FROM sessions WHERE id = ?)
            AND revoked_at IS NULL`,
      )
      .run(now, sessionId);
    return true;
  }

  rotateSession(
    sessionId: string,
    expectedSecretHash: string,
    secretHash: string,
    expiresAt: string,
    now: string,
  ): boolean {
    const result = this.db
      .prepare(
        `UPDATE sessions
            SET secret_hash = ?, expires_at = ?, last_seen_at = ?, rotated_at = ?
          WHERE id = ?
            AND secret_hash = ?
            AND revoked_at IS NULL
            AND (
              device_id IS NULL
              OR EXISTS (
                SELECT 1
                  FROM devices d
                 WHERE d.id = sessions.device_id
                   AND d.account_id = sessions.account_id
                   AND d.revoked_at IS NULL
              )
            )`,
      )
      .run(secretHash, expiresAt, now, now, sessionId, expectedSecretHash);
    return result.changes === 1;
  }

  revokeSession(sessionId: string, reason: string, now: string): void {
    this.db
      .prepare(
        `UPDATE sessions
            SET revoked_at = COALESCE(revoked_at, ?),
                revoke_reason = COALESCE(revoke_reason, ?)
          WHERE id = ?`,
      )
      .run(now, reason, sessionId);
  }

  /**
   * A password rotation invalidates pending browser authorization alongside
   * existing Cloud Sessions. Keep both writes in the caller's transaction so
   * no code can be exchanged between session revocation and code revocation.
   */
  private revokePendingOAuthAuthorizations(accountId: string, reason: string, now: string): void {
    this.db
      .prepare(
        `UPDATE oauth_authorization_codes
            SET consumed_at = ?, consume_reason = ?
          WHERE account_id = ? AND consumed_at IS NULL`,
      )
      .run(now, reason, accountId);
  }

  private revokeAllSessions(accountId: string, reason: string, now: string): void {
    this.db
      .prepare(
        `UPDATE sessions
            SET revoked_at = COALESCE(revoked_at, ?),
                revoke_reason = COALESCE(revoke_reason, ?)
          WHERE account_id = ? AND revoked_at IS NULL`,
      )
      .run(now, reason, accountId);
  }
}

function mapAccount(row: AccountRow): AccountRecord {
  return {
    id: row.id,
    username: row.username,
    usernameNormalized: row.username_normalized,
    passwordHash: row.password_hash,
    passwordVersion: row.password_version,
    isAllowed: row.is_allowed === 1,
    disabledAt: row.disabled_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    passwordChangedAt: row.password_changed_at,
    lastLoginAt: row.last_login_at,
  };
}
