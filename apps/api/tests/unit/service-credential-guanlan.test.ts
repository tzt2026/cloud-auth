import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  SHIYAN_AUTHENTICATE_SCOPE,
  guanlanRequestedScopesSchema,
  guanlanServiceCredentialClaimsSchema,
  serviceCredentialRequestSchema,
  shiyanServiceCredentialClaimsSchema,
} from "@uichat-mira/cloud-auth-contracts";
import {
  ServiceCredentialIssuanceError,
  issueServiceCredential,
  type IssueServiceCredentialInput,
} from "../../src/service-credentials/index.js";

const FIXED_NOW = new Date("2026-11-04T10:00:00.000Z");
const FIXED_NOW_SECONDS = Math.floor(FIXED_NOW.getTime() / 1000);
const ACCOUNT_ID = "account-0001";
const DEVICE_ID = "device-0001";

function decodeSegment(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

function expectIssuanceError(
  action: () => unknown,
  code: ServiceCredentialIssuanceError["code"],
): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(ServiceCredentialIssuanceError);
    expect((error as ServiceCredentialIssuanceError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ServiceCredentialIssuanceError ${code}`);
}

function guanlanClaims(): Record<string, unknown> {
  return {
    iss: SERVICE_CREDENTIAL_ISSUER,
    sub: ACCOUNT_ID,
    device_id: DEVICE_ID,
    aud: CLOUD_GUANLAN_AUDIENCE,
    scope: [GUANLAN_READ_SCOPE],
    consumer_id: ACCOUNT_ID,
    iat: FIXED_NOW_SECONDS,
    nbf: FIXED_NOW_SECONDS,
    exp: FIXED_NOW_SECONDS + 300,
  };
}

describe("Guanlan audience contract", () => {
  it("pins the audience and scope values the Guanlan verifier expects", () => {
    expect(CLOUD_GUANLAN_AUDIENCE).toBe("mira:cloud-guanlan");
    expect(GUANLAN_READ_SCOPE).toBe("guanlan.read");
    expect(GUANLAN_WRITE_SCOPE).toBe("guanlan.write");
    expect(SERVICE_CREDENTIAL_ISSUER).toBe("mira:cloud-auth");
  });

  it("accepts read-only and read+write Guanlan claims with a bound consumer", () => {
    expect(guanlanServiceCredentialClaimsSchema.parse(guanlanClaims())).toMatchObject({
      aud: CLOUD_GUANLAN_AUDIENCE,
      consumer_id: ACCOUNT_ID,
      scope: [GUANLAN_READ_SCOPE],
    });

    const readableWritable = {
      ...guanlanClaims(),
      scope: [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE],
    };
    expect(guanlanServiceCredentialClaimsSchema.parse(readableWritable)).toMatchObject({
      scope: [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE],
    });
  });

  it("requires a non-blank, unaliased consumer_id", () => {
    for (const consumerId of [undefined, "", "  ", ` ${ACCOUNT_ID}`, `${ACCOUNT_ID} `, "x".repeat(129)]) {
      const claims = guanlanClaims();
      if (consumerId === undefined) {
        delete claims.consumer_id;
      } else {
        claims.consumer_id = consumerId;
      }
      expect(guanlanServiceCredentialClaimsSchema.safeParse(claims).success).toBe(false);
    }
  });

  it("binds the consumer identity to the credential subject", () => {
    // A consumer that is not the subject would let one account act for another.
    expect(
      guanlanServiceCredentialClaimsSchema.safeParse({
        ...guanlanClaims(),
        consumer_id: "account-0002",
      }).success,
    ).toBe(false);
  });

  it("never lets write replace read or drift out of canonical order", () => {
    for (const scope of [
      [GUANLAN_WRITE_SCOPE],
      [GUANLAN_WRITE_SCOPE, GUANLAN_READ_SCOPE],
      [GUANLAN_READ_SCOPE, GUANLAN_READ_SCOPE],
      [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE, GUANLAN_WRITE_SCOPE],
      [],
    ]) {
      expect(
        guanlanServiceCredentialClaimsSchema.safeParse({ ...guanlanClaims(), scope }).success,
      ).toBe(false);
    }
  });

  it("keeps Guanlan claims isolated from the existing audiences", () => {
    // A consumer_id on the Shiyan contract is unexpected and must be rejected.
    expect(
      shiyanServiceCredentialClaimsSchema.safeParse({
        ...guanlanClaims(),
        aud: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      }).success,
    ).toBe(false);
    // The Guanlan contract does not accept another service's scope or audience.
    expect(
      guanlanServiceCredentialClaimsSchema.safeParse({
        ...guanlanClaims(),
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      }).success,
    ).toBe(false);
    expect(
      guanlanServiceCredentialClaimsSchema.safeParse({ ...guanlanClaims(), account_id: ACCOUNT_ID })
        .success,
    ).toBe(false);
  });
});

describe("Guanlan issuance request contract", () => {
  it("defaults to no explicit scope request and accepts an ordered subset", () => {
    expect(serviceCredentialRequestSchema.parse({ audience: CLOUD_GUANLAN_AUDIENCE })).toEqual({
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(
      guanlanRequestedScopesSchema.parse([GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE]),
    ).toEqual([GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE]);
    expect(guanlanRequestedScopesSchema.parse([GUANLAN_WRITE_SCOPE, GUANLAN_READ_SCOPE])).toEqual([
      GUANLAN_WRITE_SCOPE,
      GUANLAN_READ_SCOPE,
    ]);
  });

  it("rejects write-only, repeated and unknown scope requests", () => {
    for (const scopes of [
      [],
      [GUANLAN_WRITE_SCOPE],
      [GUANLAN_READ_SCOPE, GUANLAN_READ_SCOPE],
      [GUANLAN_READ_SCOPE, "guanlan.admin"],
    ]) {
      expect(
        serviceCredentialRequestSchema.safeParse({ audience: CLOUD_GUANLAN_AUDIENCE, scopes })
          .success,
      ).toBe(false);
    }
  });

  it("rejects client-supplied identity, consumer and Relay context", () => {
    for (const body of [
      { audience: CLOUD_GUANLAN_AUDIENCE, consumer_id: ACCOUNT_ID },
      { audience: CLOUD_GUANLAN_AUDIENCE, accountId: ACCOUNT_ID },
      { audience: CLOUD_GUANLAN_AUDIENCE, deviceId: DEVICE_ID },
      { audience: CLOUD_GUANLAN_AUDIENCE, relay: { room: "room-1", role: "client" } },
    ]) {
      expect(serviceCredentialRequestSchema.safeParse(body).success).toBe(false);
    }
  });
});

describe("Guanlan signing", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const baseInput = (): IssueServiceCredentialInput => ({
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    audience: CLOUD_GUANLAN_AUDIENCE,
    scope: [GUANLAN_READ_SCOPE],
    consumerId: ACCOUNT_ID,
  });

  it("signs the derived consumer and canonical scope into the claims", () => {
    const token = issueServiceCredential(
      { privateKey, keyId: "cloud-auth-2026-11", now: () => FIXED_NOW },
      { ...baseInput(), scope: [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE] },
    );

    expect(decodeSegment(token.split(".")[1]!)).toEqual({
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: ACCOUNT_ID,
      device_id: DEVICE_ID,
      aud: CLOUD_GUANLAN_AUDIENCE,
      scope: [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE],
      consumer_id: ACCOUNT_ID,
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + 300,
    });
  });

  it("refuses a Guanlan credential without a consumer", () => {
    expectIssuanceError(() => {
      const input = baseInput();
      delete input.consumerId;
      issueServiceCredential({ privateKey, keyId: "cloud-auth-2026-11" }, input);
    }, "INVALID_INPUT");
  });

  it("refuses to stamp a consumer that is not the credential subject", () => {
    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey, keyId: "cloud-auth-2026-11" },
          { ...baseInput(), consumerId: "account-0002" },
        ),
      "INVALID_INPUT",
    );
  });

  it("refuses to stamp a consumer onto a non-Guanlan audience", () => {
    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey, keyId: "cloud-auth-2026-11" },
          {
            ...baseInput(),
            audience: CLOUD_SHIYAN_AUDIENCE,
            scope: [SHIYAN_AUTHENTICATE_SCOPE],
          },
        ),
      "INVALID_INPUT",
    );
  });
});
