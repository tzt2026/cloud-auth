import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createTestAuth } from "../helpers/auth.js";
import { backfillGuanlanRegistrations, createGuanlanRegistrationTransport, deliverGuanlanRegistrations, listGuanlanRegistrations, retryGuanlanRegistration, GUANLAN_REGISTRATION_MAX_ATTEMPTS } from "../../src/guanlan-registration.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(p => rmSync(p, {recursive:true, force:true})));
function fixture() {
  const dir = mkdtempSync(join(tmpdir(),"gln-012-")); dirs.push(dir);
  return createTestAuth(join(dir,"auth.sqlite"));
}
describe("GLN-012 durable Guanlan space registration", () => {
  it("atomically enqueues account creation, backfill stays idempotent, and requires durable remote receipt", async () => {
    const {db,service} = fixture();
    const a=await service.provisionAccount("alice","strong account passphrase");
    expect(listGuanlanRegistrations(db)).toMatchObject([{accountId:a.id,status:"pending",attempts:0}]);
    expect(backfillGuanlanRegistrations(db,new Date().toISOString())).toBe(0);
    const sent:string[]=[];
    const first=await deliverGuanlanRegistrations(db,{send:async id=>{sent.push(id);return false;}});
    expect(first).toMatchObject({failed:1,delivered:0});
    expect(sent).toEqual([a.id]);
    expect(listGuanlanRegistrations(db)[0]).toMatchObject({status:"pending",attempts:1,lastError:"delivery_unconfirmed"});
    expect(retryGuanlanRegistration(db,a.id,new Date().toISOString())).toBe(false);
    const second=await deliverGuanlanRegistrations(db,{send:async id=>{sent.push(id);return true;}},{now:()=>new Date(Date.now()+31_000)});
    expect(second.delivered).toBe(1);
    expect(listGuanlanRegistrations(db)[0]!.status).toBe("delivered");
    expect(backfillGuanlanRegistrations(db,new Date().toISOString())).toBe(0);
    db.close();
  });
  it("withholds disabled accounts and rejects manual retries until enabled", async()=>{
    const {db,service}=fixture();
    const a=await service.provisionAccount("alice","strong account passphrase");
    service.setDisabled("alice",true);
    expect(listGuanlanRegistrations(db)[0]!.status).toBe("withheld");
    expect(retryGuanlanRegistration(db,a.id,new Date().toISOString())).toBe(false);
    expect((await deliverGuanlanRegistrations(db,{send:async()=>{throw Error("must not deliver");}})).delivered).toBe(0);
    service.setDisabled("alice",false);
    expect(listGuanlanRegistrations(db)[0]!.status).toBe("pending");
    db.close();
  });
  it("stops after the finite automatic retry budget and requires explicit retry", async () => {
    const {db,service}=fixture();
    const a=await service.provisionAccount("retry-limit","strong account passphrase");
    let clock=Date.now();
    const now=()=>new Date(clock);
    for(let i=0;i<GUANLAN_REGISTRATION_MAX_ATTEMPTS;i++){
      const result=await deliverGuanlanRegistrations(db,{send:async()=>false},{now});
      expect(result.failed).toBe(1);
      clock+=4_000_000;
    }
    expect(listGuanlanRegistrations(db)[0]!.status).toBe("failed");
    expect(listGuanlanRegistrations(db)[0]!.attempts).toBe(GUANLAN_REGISTRATION_MAX_ATTEMPTS);
    // Reconciliation-style access toggles must not bypass the explicit retry command.
    service.setDisabled("retry-limit",true);
    expect(listGuanlanRegistrations(db)[0]!).toMatchObject({status:"failed",attempts:GUANLAN_REGISTRATION_MAX_ATTEMPTS});
    service.setDisabled("retry-limit",false);
    service.setAllowed("retry-limit",false);
    expect(listGuanlanRegistrations(db)[0]!).toMatchObject({status:"failed",attempts:GUANLAN_REGISTRATION_MAX_ATTEMPTS});
    service.setAllowed("retry-limit",true);
    expect(listGuanlanRegistrations(db)[0]!).toMatchObject({status:"failed",attempts:GUANLAN_REGISTRATION_MAX_ATTEMPTS});
    clock+=4_000_000;
    expect((await deliverGuanlanRegistrations(db,{send:async()=>{throw Error("terminal failure must not auto-retry");}},{now})).failed).toBe(0);
    expect(retryGuanlanRegistration(db,a.id,now().toISOString())).toBe(true);
    expect(listGuanlanRegistrations(db)[0]!).toMatchObject({status:"pending",attempts:0});
    db.close();
  });
  it("recovers a process interruption after the final leased attempt", async () => {
    const {db,service}=fixture();
    const a=await service.provisionAccount("interrupted","strong account passphrase");
    const expired="2020-01-01T00:00:00.000Z";
    db.prepare("UPDATE guanlan_registration_outbox SET status='delivering', attempts=?, lease_until=? WHERE account_id=?")
      .run(GUANLAN_REGISTRATION_MAX_ATTEMPTS, expired, a.id);
    await deliverGuanlanRegistrations(db,{send:async()=>{throw Error("exhausted lease must not be delivered");}},{now:()=>new Date("2026-11-02T00:00:00.000Z")});
    expect(listGuanlanRegistrations(db)[0]!).toMatchObject({status:"failed",attempts:GUANLAN_REGISTRATION_MAX_ATTEMPTS,lastError:"delivery_interrupted_after_max_attempts"});
    expect(retryGuanlanRegistration(db,a.id,"2026-11-02T00:00:00.000Z")).toBe(true);
    expect(listGuanlanRegistrations(db)[0]!).toMatchObject({status:"pending",attempts:0});
    db.close();
  });
  it("enqueues a legacy account reactivated after active-only backfill", async () => {
    const {db,service}=fixture();
    const a=await service.provisionAccount("legacy-disabled","strong account passphrase");
    service.setDisabled("legacy-disabled",true);
    db.prepare("DELETE FROM guanlan_registration_outbox WHERE account_id=?").run(a.id);
    expect(backfillGuanlanRegistrations(db,new Date().toISOString())).toBe(0);
    expect(listGuanlanRegistrations(db)).toHaveLength(0);
    service.setAllowed("legacy-disabled",true);
    expect(listGuanlanRegistrations(db)).toHaveLength(0);
    service.setDisabled("legacy-disabled",false);
    expect(listGuanlanRegistrations(db)).toMatchObject([{accountId:a.id,status:"pending",attempts:0}]);

    const denied=await service.provisionAccount("legacy-denied","strong account passphrase");
    service.setAllowed("legacy-denied",false);
    db.prepare("DELETE FROM guanlan_registration_outbox WHERE account_id=?").run(denied.id);
    service.setDisabled("legacy-denied",false);
    expect(listGuanlanRegistrations(db)).toHaveLength(1);
    service.setAllowed("legacy-denied",true);
    expect(listGuanlanRegistrations(db)).toHaveLength(2);
    db.close();
  });
  it("validates signed transport config and rejects false success receipts",async()=>{
    expect(()=>createGuanlanRegistrationTransport("http://example.com","x".repeat(32))).toThrow();
    const responses: unknown[]=[{registered:false,accountId:"a"}, {registered:true,accountId:"b"}, {registered:true,accountId:"a"}];
    const t=createGuanlanRegistrationTransport("https://guanlan.example/internal/register","x".repeat(32),async (_url,init)=>{
      expect(init?.method).toBe("POST");
      expect(new Headers(init?.headers).get("x-mira-signature")).toMatch(/^sha256=[0-9a-f]{64}$/);
      return new Response(JSON.stringify(responses.shift()),{status:200,headers:{"content-type":"application/json"}});
    });
    expect(await t.send("a")).toBe(false);expect(await t.send("a")).toBe(false);expect(await t.send("a")).toBe(true);
  });
});
