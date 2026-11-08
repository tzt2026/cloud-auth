import { describe, expect, it } from "vitest";
import {
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  CLOUD_WHO_YOU_AUDIENCE,
  RELAY_TRANSPORT_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  SHIYAN_AUTHENTICATE_SCOPE,
  WHOYOU_MAIL_SEND_SCOPE,
  WHOYOU_MAIL_WRITE_SCOPE,
  WHOYOU_READ_SCOPE,
  relayServiceCredentialClaimsSchema,
  relayTicketContextSchema,
  serviceCredentialClaimsSchema,
  serviceCredentialJwtHeaderSchema,
  shiyanServiceCredentialClaimsSchema,
  whoYouServiceCredentialClaimsSchema,
} from "@uichat-mira/cloud-auth-contracts";

const temporal = { iat: 1_790_000_000, nbf: 1_790_000_000, exp: 1_790_000_300 };

const shiyanClaims = {
  iss: SERVICE_CREDENTIAL_ISSUER,
  sub: "account-0001",
  device_id: "device-0001",
  aud: CLOUD_SHIYAN_AUDIENCE,
  scope: [SHIYAN_AUTHENTICATE_SCOPE],
  ...temporal,
};

const relayClaims = {
  iss: SERVICE_CREDENTIAL_ISSUER,
  sub: "account-0001",
  device_id: "device-0001",
  aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
  scope: [RELAY_TRANSPORT_SCOPE],
  relay: { room: "room-7f3a", role: "client" },
  ...temporal,
};

describe("service credential shared contract", () => {
  it("pins the stable audience, issuer and scope literals", () => {
    expect(SERVICE_CREDENTIAL_ISSUER).toBe("mira:cloud-auth");
    expect(CLOUD_SHIYAN_AUDIENCE).toBe("mira:cloud-shiyan");
    expect(CLOUD_RELAY_TRANSPORT_AUDIENCE).toBe("mira:cloud-relay-transport");
    expect(SHIYAN_AUTHENTICATE_SCOPE).toBe("shiyan:authenticate");
    expect(RELAY_TRANSPORT_SCOPE).toBe("relay:transport");
  });

  it("accepts only the canonical claims shape per audience", () => {
    expect(serviceCredentialClaimsSchema.parse(shiyanClaims)).toEqual(shiyanClaims);
    expect(serviceCredentialClaimsSchema.parse(relayClaims)).toEqual(relayClaims);
    expect(shiyanServiceCredentialClaimsSchema.parse(shiyanClaims)).toEqual(shiyanClaims);
    expect(relayServiceCredentialClaimsSchema.parse(relayClaims)).toEqual(relayClaims);
  });

  it("rejects cross-audience scope and context combinations", () => {
    for (const payload of [
      { ...shiyanClaims, scope: [RELAY_TRANSPORT_SCOPE] },
      { ...shiyanClaims, scope: [] },
      { ...shiyanClaims, scope: [SHIYAN_AUTHENTICATE_SCOPE, RELAY_TRANSPORT_SCOPE] },
      { ...shiyanClaims, relay: { room: "room-7f3a", role: "client" } },
      { ...relayClaims, relay: undefined },
      { ...relayClaims, scope: [SHIYAN_AUTHENTICATE_SCOPE] },
      { ...relayClaims, relay: { room: "room-7f3a", role: "owner" } },
      { ...relayClaims, relay: { room: "room 7f3a", role: "client" } },
      { ...relayClaims, remote: { terminal: true } },
      { ...relayClaims, scope: [RELAY_TRANSPORT_SCOPE, "remote:terminal"] },
    ]) {
      expect(serviceCredentialClaimsSchema.safeParse(payload).success).toBe(false);
    }
  });

  it("rejects missing identity and invalid temporal claims", () => {
    for (const payload of [
      { ...shiyanClaims, iss: "" },
      { ...shiyanClaims, sub: "" },
      { ...shiyanClaims, device_id: "" },
      { ...shiyanClaims, iat: undefined },
      { ...shiyanClaims, nbf: undefined },
      { ...shiyanClaims, exp: undefined },
      { ...shiyanClaims, iat: 1.5 },
      { ...shiyanClaims, exp: temporal.iat },
      { ...shiyanClaims, nbf: temporal.iat - 1 },
    ]) {
      expect(serviceCredentialClaimsSchema.safeParse(payload).success).toBe(false);
    }
  });

  it("accepts only EdDSA/JWT headers with a bounded kid", () => {
    expect(
      serviceCredentialJwtHeaderSchema.parse({
        alg: "EdDSA",
        typ: "JWT",
        kid: "cloud-auth-2026-10",
      }),
    ).toEqual({ alg: "EdDSA", typ: "JWT", kid: "cloud-auth-2026-10" });

    for (const header of [
      { alg: "none", typ: "JWT", kid: "key-1" },
      { alg: "HS256", typ: "JWT", kid: "key-1" },
      { alg: "EdDSA", typ: "JWS", kid: "key-1" },
      { alg: "EdDSA", typ: "JWT" },
      { alg: "EdDSA", typ: "JWT", kid: "" },
      { alg: "EdDSA", typ: "JWT", kid: "key with spaces" },
      { alg: "EdDSA", typ: "JWT", kid: "k".repeat(65) },
      { alg: "EdDSA", typ: "JWT", kid: "key-1", extra: true },
    ]) {
      expect(serviceCredentialJwtHeaderSchema.safeParse(header).success).toBe(false);
    }
  });

  it("validates Relay context as transport identity only", () => {
    expect(relayTicketContextSchema.parse({ room: "room-7f3a", role: "host" })).toEqual({
      room: "room-7f3a",
      role: "host",
    });

    for (const context of [
      { room: "room-7f3a", role: "owner" },
      { room: "", role: "client" },
      { room: "room with spaces", role: "client" },
      { room: "r".repeat(129), role: "client" },
      { room: "room-7f3a", role: "client", tool: "terminal" },
    ]) {
      expect(relayTicketContextSchema.safeParse(context).success).toBe(false);
    }
  });
});

const whoYouReadClaims = {
  iss: SERVICE_CREDENTIAL_ISSUER,
  sub: "account-0001",
  device_id: "device-0001",
  aud: CLOUD_WHO_YOU_AUDIENCE,
  scope: [WHOYOU_READ_SCOPE],
  consumer_id: "account-0001",
  ...temporal,
};

const whoYouWriteClaims = {
  ...whoYouReadClaims,
  scope: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE],
};

const whoYouSendClaims = {
  ...whoYouReadClaims,
  scope: [WHOYOU_MAIL_SEND_SCOPE],
  confirmation: {
    actor: "user",
    draft_id: "dr_0123456789abcdef",
    draft_version: 7,
    content_hash: "a".repeat(64),
    nonce: "nonce-0123456789abcdef",
  },
};

describe("Who You service credential contract", () => {
  it("pins Who You audience and scope literals", () => {
    expect(CLOUD_WHO_YOU_AUDIENCE).toBe("mira:who-you");
    expect(WHOYOU_READ_SCOPE).toBe("whoyou.read");
    expect(WHOYOU_MAIL_WRITE_SCOPE).toBe("whoyou.mail.write");
    expect(WHOYOU_MAIL_SEND_SCOPE).toBe("whoyou.mail.send");
  });

  it("accepts the canonical read, write and send shapes", () => {
    for (const claims of [whoYouReadClaims, whoYouWriteClaims, whoYouSendClaims]) {
      expect(serviceCredentialClaimsSchema.parse(claims)).toEqual(claims);
      expect(whoYouServiceCredentialClaimsSchema.parse(claims)).toEqual(claims);
    }
  });

  it("rejects scope sets that are not canonical", () => {
    for (const payload of [
      { ...whoYouReadClaims, scope: [] },
      { ...whoYouReadClaims, scope: [WHOYOU_MAIL_WRITE_SCOPE, WHOYOU_READ_SCOPE] },
      { ...whoYouReadClaims, scope: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE, WHOYOU_MAIL_SEND_SCOPE] },
      { ...whoYouReadClaims, scope: [WHOYOU_MAIL_SEND_SCOPE, WHOYOU_READ_SCOPE] },
      { ...whoYouWriteClaims, scope: [WHOYOU_MAIL_WRITE_SCOPE] },
    ]) {
      expect(whoYouServiceCredentialClaimsSchema.safeParse(payload).success).toBe(false);
    }
  });

  it("requires a confirmation for send and forbids it elsewhere", () => {
    const { confirmation: confirmationValue } = whoYouSendClaims;
    for (const payload of [
      { ...whoYouSendClaims, confirmation: undefined },
      { ...whoYouReadClaims, confirmation: confirmationValue },
      { ...whoYouWriteClaims, confirmation: confirmationValue },
    ]) {
      expect(whoYouServiceCredentialClaimsSchema.safeParse(payload).success).toBe(false);
    }
  });

  it("rejects malformed draft binding and nonce values", () => {
    const confirmation = whoYouSendClaims.confirmation;
    for (const payload of [
      { ...whoYouSendClaims, consumer_id: "account-0002" },
      { ...whoYouSendClaims, confirmation: { ...confirmation, actor: "device" } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, draft_id: "draft with spaces" } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, draft_id: "d".repeat(129) } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, draft_version: 0 } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, draft_version: 1.5 } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, content_hash: "A".repeat(64) } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, content_hash: "a".repeat(63) } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, nonce: "short" } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, nonce: "nonce with spaces" } },
      { ...whoYouSendClaims, confirmation: { ...confirmation, extra: true } },
    ]) {
      expect(whoYouServiceCredentialClaimsSchema.safeParse(payload).success).toBe(false);
    }
  });

  it("keeps Who You credentials non-interchangeable with other audiences", () => {
    expect(
      whoYouServiceCredentialClaimsSchema.safeParse({
        ...whoYouReadClaims,
        aud: CLOUD_SHIYAN_AUDIENCE,
      }).success,
    ).toBe(false);
    expect(
      serviceCredentialClaimsSchema.safeParse({
        ...shiyanClaims,
        consumer_id: "account-0001",
      }).success,
    ).toBe(false);
  });
});
