import type { DatabaseSync } from "node:sqlite";

export type GuanlanSpaceStatus = "ready" | "not_registered" | "unavailable";

/**
 * Whether Cloud Auth may consider a verified account's Guanlan space usable.
 *
 * The authoritative account/consumer rows live in Guanlan; Cloud Auth only
 * knows its own durable registration projection (GLN-012). Issuance therefore
 * fails closed unless that projection says `delivered`.
 */
export interface GuanlanSpaceReadiness {
  status(accountId: string): GuanlanSpaceStatus;
}

const OUTBOX_TABLE = "guanlan_registration_outbox";

/**
 * Reads the GLN-012 registration outbox on the same SQLite connection as the
 * issuance transaction.
 *
 * The table is owned by GLN-012 (`migrations/008_guanlan_registration_outbox.sql`,
 * merged in `dev` `931ae6c`): account creation enqueues `pending` and only a
 * confirmed delivery moves a row to `delivered`. A missing table (migration not
 * applied, or an older database) resolves to `unavailable`, which callers must
 * treat as fail-closed rather than as permission. No Guanlan business data is
 * stored here.
 */
export class GuanlanRegistrationOutboxReadiness implements GuanlanSpaceReadiness {
  constructor(private readonly db: DatabaseSync) {}

  status(accountId: string): GuanlanSpaceStatus {
    if (!this.outboxExists()) return "unavailable";

    const row = this.db
      .prepare(`SELECT status FROM ${OUTBOX_TABLE} WHERE account_id = ?`)
      .get(accountId) as { status?: unknown } | undefined;
    if (!row) return "not_registered";
    return row.status === "delivered" ? "ready" : "not_registered";
  }

  private outboxExists(): boolean {
    const row = this.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(OUTBOX_TABLE) as { name?: unknown } | undefined;
    return typeof row?.name === "string";
  }
}
