import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { openDatabase } from "../../src/storage/database.js";

const cleanup: string[] = [];

afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("SQLite runtime", () => {
  it("enables WAL and applies migrations once", () => {
    const dir = mkdtempSync(join(tmpdir(), "mira-auth-db-"));
    cleanup.push(dir);
    const path = join(dir, "auth.sqlite");

    const first = openDatabase({ databasePath: path });
    const journal = first.prepare("PRAGMA journal_mode").get() as { journal_mode?: string };
    expect(journal.journal_mode?.toLowerCase()).toBe("wal");
    expect(first.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({ count: 8 });
    first.close();

    const second = openDatabase({ databasePath: path });
    expect(second.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toMatchObject({ count: 8 });
    second.close();
  });
});
