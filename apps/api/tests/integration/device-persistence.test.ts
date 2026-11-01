import { randomUUID } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuthError } from "../../src/auth/auth-service.js";
import { parseSessionToken } from "../../src/security/session-token.js";
import { createTestAuth } from "../helpers/auth.js";

const cleanup: string[] = [];
const password = "correct horse battery staple";

afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("Mira Device SQLite persistence", () => {
  it("applies the additive device migration and preserves devices across reopen", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mira-device-persistence-"));
    cleanup.push(dir);
    const databasePath = join(dir, "auth.sqlite");
    const v2Migrations = join(dir, "migrations-v2");
    mkdirSync(v2Migrations);
    for (const migration of ["001_service_metadata.sql", "002_accounts_sessions.sql"]) {
      copyFileSync(join(process.cwd(), "migrations", migration), join(v2Migrations, migration));
    }

    const first = createTestAuth(databasePath, v2Migrations);
    expect(first.db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({
      count: 2,
    });
    // Simulate an account created before GLN-012 migration existed.
    const historical = first.repository.createAccount("alice", "alice", "historical-password-hash", new Date().toISOString());
    expect(historical.id).toBeTruthy();
    // Upgrade and restore a real password before exercising login on the new schema.
    first.db.close();

    const second = createTestAuth(databasePath);
    expect(second.db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({
      count: 8,
    });
    expect(second.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'devices'").get()).toMatchObject({
      name: "devices",
    });
    second.repository.updatePasswordAndRevokeSessions(historical.id, "temporary", new Date().toISOString());
    // The pre-migration account remains available after schema upgrade.
    expect(second.repository.findAccountById(historical.id)?.username).toBe("alice");

    const alice = await second.service.provisionAccount("alice2", password);
    const aliceSession = await second.service.login("alice2", password, "127.0.0.1");
    const desktop = second.deviceService.register(aliceSession.sessionToken, {
      installationId: randomUUID(),
      platform: "desktop",
      clientName: "Mira Desktop",
      clientVersion: "1.0.0",
    });
    const aliceMobileSession = await second.service.login("alice2", password, "127.0.0.4");
    const mobile = second.deviceService.register(aliceMobileSession.sessionToken, {
      installationId: randomUUID(),
      platform: "mobile",
      clientName: "Mira Mobile",
      clientVersion: "2.0.0",
    });
    second.db
      .prepare("UPDATE devices SET revoked_at = ?, revoke_reason = ? WHERE id = ?")
      .run("2026-10-24T08:00:00.000Z", "user_revoked", mobile.id);

    await second.service.provisionAccount("bob", password);
    const bob = await second.service.login("bob", password, "127.0.0.2");
    const bobDevice = second.deviceService.register(bob.sessionToken, {
      installationId: randomUUID(),
      platform: "desktop",
    });
    second.db.close();

    const third = createTestAuth(databasePath);
    expect(third.db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({
      count: 8,
    });

    const aliceDevices = third.deviceService.list(aliceSession.sessionToken);
    expect(aliceDevices.map((device) => device.id).sort()).toEqual(
      [desktop.id, mobile.id].sort(),
    );
    expect(aliceDevices.find((device) => device.id === desktop.id)).toMatchObject({
      platform: "desktop",
      clientName: "Mira Desktop",
      clientVersion: "1.0.0",
    });
    expect(aliceDevices.find((device) => device.id === mobile.id)).toMatchObject({
      platform: "mobile",
      clientName: "Mira Mobile",
      clientVersion: "2.0.0",
      revokedAt: "2026-10-24T08:00:00.000Z",
    });

    const bobDevices = third.deviceService.list(bob.sessionToken);
    expect(bobDevices).toEqual([bobDevice]);

    const columns = third.db.prepare("PRAGMA table_info(devices)").all() as Array<{
      name: string;
      notnull: number;
    }>;
    expect(columns.map((column) => column.name)).toEqual([
      "id",
      "account_id",
      "installation_id",
      "platform",
      "client_name",
      "client_version",
      "public_key",
      "created_at",
      "last_seen_at",
      "revoked_at",
      "revoke_reason",
    ]);
    expect(columns.find((column) => column.name === "public_key")?.notnull).toBe(0);
    expect(columns.some((column) => /imei|mac|serial|fingerprint|hardware/i.test(column.name))).toBe(
      false,
    );

    const sessionColumns = third.db.prepare("PRAGMA table_info(sessions)").all() as Array<{
      name: string;
      notnull: number;
    }>;
    expect(sessionColumns.find((column) => column.name === "device_id")?.notnull).toBe(0);
    expect(
      third.db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_sessions_device_id'",
        )
        .get(),
    ).toMatchObject({ name: "idx_sessions_device_id" });

    third.db.close();
  });

  it("persists device-bound session revocation across reopen and keeps legacy sessions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mira-device-session-persistence-"));
    cleanup.push(dir);
    const databasePath = join(dir, "auth.sqlite");

    const first = createTestAuth(databasePath);
    await first.service.provisionAccount("alice", password);
    const desktopLogin = await first.service.login("alice", password, "127.0.0.1");
    const mobileLogin = await first.service.login("alice", password, "127.0.0.2");
    const legacyLogin = await first.service.login("alice", password, "127.0.0.3");

    const desktop = first.deviceService.register(desktopLogin.sessionToken, {
      installationId: randomUUID(),
      platform: "desktop",
      clientName: "Mira Desktop",
    });
    const mobile = first.deviceService.register(mobileLogin.sessionToken, {
      installationId: randomUUID(),
      platform: "mobile",
      clientName: "Mira Mobile",
    });
    const revoked = first.deviceService.revoke(desktopLogin.sessionToken, desktop.id);
    expect(revoked.revokedAt).not.toBeNull();

    const desktopSessionId = parseSessionToken(desktopLogin.sessionToken)?.id;
    const mobileSessionId = parseSessionToken(mobileLogin.sessionToken)?.id;
    const legacySessionId = parseSessionToken(legacyLogin.sessionToken)?.id;
    expect(desktopSessionId).toBeTruthy();
    expect(mobileSessionId).toBeTruthy();
    expect(legacySessionId).toBeTruthy();
    first.db.close();

    const second = createTestAuth(databasePath);
    expect(
      second.db
        .prepare("SELECT device_id, revoked_at, revoke_reason FROM sessions WHERE id = ?")
        .get(desktopSessionId!) as {
        device_id: string | null;
        revoked_at: string | null;
        revoke_reason: string | null;
      },
    ).toEqual({
      device_id: desktop.id,
      revoked_at: revoked.revokedAt,
      revoke_reason: "device_revoked",
    });
    expect(
      second.db
        .prepare("SELECT device_id, revoked_at FROM sessions WHERE id = ?")
        .get(mobileSessionId!) as { device_id: string | null; revoked_at: string | null },
    ).toEqual({ device_id: mobile.id, revoked_at: null });
    expect(
      second.db
        .prepare("SELECT device_id, revoked_at FROM sessions WHERE id = ?")
        .get(legacySessionId!) as { device_id: string | null; revoked_at: string | null },
    ).toEqual({ device_id: null, revoked_at: null });
    expect(
      second.db.prepare("SELECT revoked_at FROM devices WHERE id = ?").get(desktop.id),
    ).toMatchObject({ revoked_at: revoked.revokedAt });

    for (const action of [
      () => second.service.getSession(desktopLogin.sessionToken),
      () => second.service.renewSession(desktopLogin.sessionToken),
    ]) {
      try {
        action();
        throw new Error("Expected the revoked device session to stay rejected");
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError);
        expect(error).toMatchObject({ code: "AUTH_REAUTH_REQUIRED", statusCode: 401 });
      }
    }

    expect(second.service.getSession(mobileLogin.sessionToken).account.username).toBe("alice");
    expect(second.service.renewSession(mobileLogin.sessionToken).account.username).toBe("alice");
    expect(second.service.getSession(legacyLogin.sessionToken).account.username).toBe("alice");
    const renewedLegacy = second.service.renewSession(legacyLogin.sessionToken);
    expect(renewedLegacy.account.username).toBe("alice");

    expect(second.deviceService.list(renewedLegacy.sessionToken)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: desktop.id, revokedAt: revoked.revokedAt }),
        expect.objectContaining({ id: mobile.id, revokedAt: null }),
      ]),
    );

    second.db.close();
  });
});
