import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { issueSessionToken } from "../../src/security/session-token.js";
import { createTestAuth } from "../helpers/auth.js";

const cleanup: string[] = [];
const password = "correct horse battery staple";

afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("auth persistence", () => {
  it("restores a valid Cloud Session after SQLite/service reopen", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mira-auth-reopen-"));
    cleanup.push(dir);
    const databasePath = join(dir, "auth.sqlite");

    const first = createTestAuth(databasePath);
    await first.service.provisionAccount("persistent", password);
    const login = await first.service.login("persistent", password, "127.0.0.1");
    first.db.close();

    const second = createTestAuth(databasePath);
    expect(second.service.getSession(login.sessionToken)).toMatchObject({
      account: { username: "persistent" },
    });

    const renewed = second.service.renewSession(login.sessionToken);
    second.db.close();

    const third = createTestAuth(databasePath);
    expect(third.service.getSession(renewed.sessionToken)).toMatchObject({
      account: { username: "persistent" },
    });
    third.db.close();
  });

  it("cannot mint a session from a password version that was reset during verification", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mira-auth-race-"));
    cleanup.push(dir);
    const databasePath = join(dir, "auth.sqlite");

    const context = createTestAuth(databasePath);
    await context.service.provisionAccount("raceuser", password);
    const beforeReset = context.repository.findAccountByUsername("raceuser");
    expect(beforeReset).not.toBeNull();

    await context.service.resetPassword("raceuser", "replacement passphrase for race test");
    const issued = issueSessionToken();
    const created = context.repository.createSessionIfAccountActive(
      issued.id,
      beforeReset!.id,
      beforeReset!.passwordVersion,
      issued.secretHash,
      new Date(Date.now() + 3600_000).toISOString(),
      new Date().toISOString(),
    );

    expect(created).toBe(false);
    context.db.close();
  });

  it("keeps migration application idempotent with the auth schema", () => {
    const dir = mkdtempSync(join(tmpdir(), "mira-auth-migrations-"));
    cleanup.push(dir);
    const databasePath = join(dir, "auth.sqlite");

    const first = createTestAuth(databasePath);
    expect(first.db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({ count: 8 });
    first.db.close();

    const second = createTestAuth(databasePath);
    expect(second.db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({ count: 8 });
    second.db.close();
  });
});
