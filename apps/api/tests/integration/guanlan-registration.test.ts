import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createTestAuth } from "../helpers/auth.js";
import { backfillGuanlanRegistrations, createGuanlanRegistrationTransport, deliverGuanlanRegistrations, listGuanlanRegistrations, retryGuanlanRegistration } from "../../src/guanlan-registration.js";

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
    expect(retryGuanlanRegistration(db,a.id,new Date().toISOString())).toBe(true);
    const second=await deliverGuanlanRegistrations(db,{send:async id=>{sent.push(id);return true;}});
    expect(second.delivered).toBe(1);
    expect(listGuanlanRegistrations(db)[0].status).toBe("delivered");
    expect(backfillGuanlanRegistrations(db,new Date().toISOString())).toBe(0);
    db.close();
  });
  it("withholds disabled accounts and rejects manual retries until enabled", async()=>{
    const {db,service}=fixture();
    const a=await service.provisionAccount("alice","strong account passphrase");
    service.setDisabled("alice",true);
    expect(listGuanlanRegistrations(db)[0].status).toBe("withheld");
    expect(retryGuanlanRegistration(db,a.id,new Date().toISOString())).toBe(false);
    expect((await deliverGuanlanRegistrations(db,{send:async()=>{throw Error("must not deliver");}})).delivered).toBe(0);
    service.setDisabled("alice",false);
    expect(listGuanlanRegistrations(db)[0].status).toBe("pending");
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
