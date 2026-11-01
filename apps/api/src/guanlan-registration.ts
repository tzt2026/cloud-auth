import { createHmac } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

/** Only Cloud Auth may enqueue and deliver; Guanlan owns its account-space data. */
export interface RegistrationRecord {
  accountId: string;
  status: "pending" | "delivering" | "delivered" | "withheld";
  attempts: number;
  nextAttemptAt: string;
  leaseUntil: string | null;
  lastError: string | null;
}

const ACTIVE_ACCOUNT = "a.is_allowed = 1 AND a.disabled_at IS NULL";

/** Run inside the same transaction as account creation. */
export function enqueueGuanlanRegistration(db: DatabaseSync, accountId: string, now: string): void {
  db.prepare("INSERT OR IGNORE INTO guanlan_registration_outbox(account_id, status, next_attempt_at, updated_at) VALUES (?, 'pending', ?, ?)").run(accountId, now, now);
}

/** Backfill only active existing accounts; terminal delivered records remain untouched. */
export function backfillGuanlanRegistrations(db: DatabaseSync, now: string): number {
  const result = db.prepare(`INSERT OR IGNORE INTO guanlan_registration_outbox(account_id,status,next_attempt_at,updated_at)
    SELECT a.id, 'pending', ?, ? FROM accounts a WHERE ${ACTIVE_ACCOUNT}`).run(now, now);
  return Number(result.changes);
}

/** When admission is revoked, no pending retries can acquire the account. */
export function withholdGuanlanRegistration(db: DatabaseSync, accountId: string, now: string): void {
  db.prepare(`UPDATE guanlan_registration_outbox SET status='withheld', lease_until=NULL, updated_at=?, last_error='account_inactive'
    WHERE account_id=? AND status != 'delivered'`).run(now, accountId);
}

/** Account reactivation schedules another attempt instead of blindly marking it delivered. */
export function resumeGuanlanRegistration(db: DatabaseSync, accountId: string, now: string): void {
  db.prepare(`UPDATE guanlan_registration_outbox SET status='pending', attempts=0, next_attempt_at=?, lease_until=NULL, last_error=NULL, updated_at=?
    WHERE account_id=? AND status='withheld'`).run(now, now, accountId);
}

export function listGuanlanRegistrations(db: DatabaseSync, accountId?: string): RegistrationRecord[] {
  const sql = `SELECT account_id AS accountId, status, attempts, next_attempt_at AS nextAttemptAt, lease_until AS leaseUntil, last_error AS lastError
    FROM guanlan_registration_outbox` + (accountId ? " WHERE account_id = ?" : "") + " ORDER BY account_id LIMIT 500";
  return (accountId ? db.prepare(sql).all(accountId) : db.prepare(sql).all()) as unknown as RegistrationRecord[];
}

export function retryGuanlanRegistration(db: DatabaseSync, accountId: string, now: string): boolean {
  const result = db.prepare(`UPDATE guanlan_registration_outbox SET status='pending', attempts=0, next_attempt_at=?, lease_until=NULL, last_error=NULL, updated_at=?
    WHERE account_id=? AND status IN ('pending','delivering')
    AND EXISTS (SELECT 1 FROM accounts a WHERE a.id=account_id AND ${ACTIVE_ACCOUNT})`).run(now, now, accountId);
  return result.changes === 1;
}

/** Atomic lease ensures a concurrent CLI invocation cannot double-send the same attempt. */
function claim(db: DatabaseSync, now: string): RegistrationRecord | null {
  db.exec("BEGIN IMMEDIATE");
  try {
    const row = db.prepare(`SELECT r.account_id AS accountId, r.status, r.attempts, r.next_attempt_at AS nextAttemptAt,
      r.lease_until AS leaseUntil, r.last_error AS lastError
      FROM guanlan_registration_outbox r JOIN accounts a ON a.id=r.account_id
      WHERE ${ACTIVE_ACCOUNT} AND (
        (r.status='pending' AND r.next_attempt_at <= ?) OR
        (r.status='delivering' AND r.lease_until <= ?)
      ) ORDER BY r.next_attempt_at, r.account_id LIMIT 1`).get(now, now) as unknown as RegistrationRecord | undefined;
    if (!row) { db.exec("COMMIT"); return null; }
    const leaseUntil = new Date(Date.parse(now) + 60_000).toISOString();
    db.prepare(`UPDATE guanlan_registration_outbox SET status='delivering', attempts=attempts+1, lease_until=?, updated_at=? WHERE account_id=?`).run(leaseUntil, now, row.accountId);
    db.exec("COMMIT");
    return { ...row, status:"delivering", attempts:row.attempts+1, leaseUntil };
  } catch (error) { db.exec("ROLLBACK"); throw error; }
}

export interface GuanlanRegistrationTransport {
  send(accountId: string): Promise<boolean>;
}

export async function deliverGuanlanRegistrations(
  db: DatabaseSync, transport: GuanlanRegistrationTransport, options: { limit?: number; now?: () => Date } = {},
): Promise<{ delivered: number; failed: number; pending: number }> {
  const limit = Math.max(1, Math.min(25, options.limit ?? 10));
  const now = options.now ?? (() => new Date());
  let delivered = 0, failed = 0;
  for (let i=0; i<limit; i++) {
    const job = claim(db, now().toISOString());
    if (!job) break;
    let confirmed = false;
    try { confirmed = await transport.send(job.accountId); } catch { /* record a sanitized retryable failure */ }
    const finished = now().toISOString();
    // A disable/deny racing with the network request wins over completion.
    if (confirmed) {
      const result = db.prepare(`UPDATE guanlan_registration_outbox SET status='delivered', lease_until=NULL, last_error=NULL, updated_at=?
        WHERE account_id=? AND status='delivering' AND lease_until=?
        AND EXISTS (SELECT 1 FROM accounts a WHERE a.id=account_id AND ${ACTIVE_ACCOUNT})`).run(finished, job.accountId, job.leaseUntil);
      delivered += Number(result.changes);
    } else {
      const seconds = Math.min(3600, 30 * 2 ** Math.min(7, job.attempts-1));
      const next = new Date(Date.parse(finished)+seconds*1000).toISOString();
      const result = db.prepare(`UPDATE guanlan_registration_outbox SET status='pending', next_attempt_at=?, lease_until=NULL,
        last_error='delivery_unconfirmed', updated_at=?
        WHERE account_id=? AND status='delivering' AND lease_until=?
        AND EXISTS (SELECT 1 FROM accounts a WHERE a.id=account_id AND ${ACTIVE_ACCOUNT})`).run(next, finished, job.accountId, job.leaseUntil);
      failed += Number(result.changes);
    }
  }
  const pending = (db.prepare("SELECT COUNT(*) AS n FROM guanlan_registration_outbox WHERE status IN ('pending','delivering')").get() as {n:number}).n;
  return {delivered, failed, pending};
}

/**
 * Authenticated inter-service contract for a future Guanlan receiver.
 * Receiver MUST verify timestamp window, signature and an idempotent accountId;
 * it must return {accountId, registered:true} only after durable commit.
 */
export function createGuanlanRegistrationTransport(
  endpoint: string, secret: string, fetcher: typeof fetch = fetch,
): GuanlanRegistrationTransport {
  const u = new URL(endpoint);
  if (u.protocol !== "https:" || !secret || secret.length < 32) throw new Error("Guanlan delivery configuration is unsafe");
  return {
    async send(accountId) {
      const payload = JSON.stringify({ version: 1, accountId });
      const timestamp = String(Math.floor(Date.now() / 1000));
      const signature = createHmac("sha256", secret).update(timestamp+"."+payload).digest("hex");
      const response = await fetcher(u, {
        method:"POST",
        headers: {"content-type":"application/json","x-mira-timestamp":timestamp,"x-mira-signature":"sha256="+signature},
        body:payload,
        signal:AbortSignal.timeout(8000),
        redirect:"error",
      });
      if (!response.ok) return false;
      const receipt: unknown = await response.json();
      return typeof receipt === "object" && receipt !== null &&
        (receipt as {accountId?: unknown}).accountId === accountId &&
        (receipt as {registered?: unknown}).registered === true;
    },
  };
}
