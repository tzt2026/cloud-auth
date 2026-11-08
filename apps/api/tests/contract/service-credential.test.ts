import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  CLOUD_WHO_YOU_AUDIENCE,
  RELAY_TRANSPORT_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  SHIYAN_AUTHENTICATE_SCOPE,
  WHOYOU_MAIL_SEND_SCOPE,
  WHOYOU_READ_SCOPE,
} from "@uichat-mira/cloud-auth-contracts";
import {
  ServiceCredentialVerificationError,
  issueServiceCredential,
  verifyServiceCredential,
  type ServiceCredentialVerifierConfig,
} from "../../src/service-credentials/index.js";

const FIXED_NOW = new Date("2026-10-24T10:00:00.000Z");
const FIXED_NOW_SECONDS = Math.floor(FIXED_NOW.getTime() / 1000);
const ACCOUNT_ID = "account-0001";
const DEVICE_ID = "device-0001";
const KEY_ID = "cloud-auth-2026-10";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const otherKeys = generateKeyPairSync("ed25519");

function signRawToken(header: unknown, payload: unknown, key: KeyObject): string {
  const headerSegment = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signature = cryptoSign(null, Buffer.from(signingInput, "ascii"), key);
  return `${signingInput}.${signature.toString("base64url")}`;
}

function shiyanClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: SERVICE_CREDENTIAL_ISSUER,
    sub: ACCOUNT_ID,
    device_id: DEVICE_ID,
    aud: CLOUD_SHIYAN_AUDIENCE,
    scope: [SHIYAN_AUTHENTICATE_SCOPE],
    iat: FIXED_NOW_SECONDS,
    nbf: FIXED_NOW_SECONDS,
    exp: FIXED_NOW_SECONDS + 300,
    ...overrides,
  };
}

function relayClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: SERVICE_CREDENTIAL_ISSUER,
    sub: ACCOUNT_ID,
    device_id: DEVICE_ID,
    aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
    scope: [RELAY_TRANSPORT_SCOPE],
    relay: { room: "room-7f3a", role: "client" },
    iat: FIXED_NOW_SECONDS,
    nbf: FIXED_NOW_SECONDS,
    exp: FIXED_NOW_SECONDS + 300,
    ...overrides,
  };
}

function header(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { alg: "EdDSA", typ: "JWT", kid: KEY_ID, ...overrides };
}

function shiyanVerifier(
  overrides: Partial<ServiceCredentialVerifierConfig> = {},
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_SHIYAN_AUDIENCE,
    publicKeys: new Map([[KEY_ID, publicKey]]),
    now: () => FIXED_NOW,
    ...overrides,
  };
}

function relayVerifier(
  overrides: Partial<ServiceCredentialVerifierConfig> = {},
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
    publicKeys: new Map([[KEY_ID, publicKey]]),
    expectedRelay: { room: "room-7f3a", role: "client" },
    now: () => FIXED_NOW,
    ...overrides,
  };
}

function issueShiyanToken(): string {
  return issueServiceCredential(
    { privateKey, keyId: KEY_ID, now: () => FIXED_NOW },
    {
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      audience: CLOUD_SHIYAN_AUDIENCE,
      scope: [SHIYAN_AUTHENTICATE_SCOPE],
    },
  );
}

function issueRelayToken(room = "room-7f3a", role: "client" | "host" = "client"): string {
  return issueServiceCredential(
    { privateKey, keyId: KEY_ID, now: () => FIXED_NOW },
    {
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      scope: [RELAY_TRANSPORT_SCOPE],
      relay: { room, role },
    },
  );
}

function expectVerificationError(
  action: () => unknown,
  code: ServiceCredentialVerificationError["code"],
): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(ServiceCredentialVerificationError);
    expect((error as ServiceCredentialVerificationError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ServiceCredentialVerificationError ${code}`);
}

describe("service credential verification contract", () => {
  it("verifies a valid Shiyan credential and returns canonical claims", () => {
    const verified = verifyServiceCredential(issueShiyanToken(), shiyanVerifier());

    expect(verified.keyId).toBe(KEY_ID);
    expect(verified.expiresAt.toISOString()).toBe("2026-10-24T10:05:00.000Z");
    expect(verified.claims).toEqual({
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: ACCOUNT_ID,
      device_id: DEVICE_ID,
      aud: CLOUD_SHIYAN_AUDIENCE,
      scope: [SHIYAN_AUTHENTICATE_SCOPE],
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + 300,
    });
  });

  it("verifies a hosted Relay ticket only against the requested room and role", () => {
    const verified = verifyServiceCredential(
      issueRelayToken("room-7f3a", "host"),
      relayVerifier({ expectedRelay: { room: "room-7f3a", role: "host" } }),
    );

    expect(verified.claims).toMatchObject({
      aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      relay: { room: "room-7f3a", role: "host" },
    });

    expectVerificationError(
      () =>
        verifyServiceCredential(
          issueRelayToken("room-7f3a", "client"),
          relayVerifier({ expectedRelay: { room: "room-7f3a", role: "host" } }),
        ),
      "RELAY_CONTEXT_MISMATCH",
    );
    expectVerificationError(
      () =>
        verifyServiceCredential(
          issueRelayToken("room-7f3a", "client"),
          relayVerifier({ expectedRelay: { room: "room-other", role: "client" } }),
        ),
      "RELAY_CONTEXT_MISMATCH",
    );
  });

  it("keeps Shiyan and Relay audiences non-interchangeable", () => {
    expectVerificationError(
      () => verifyServiceCredential(issueShiyanToken(), relayVerifier()),
      "AUDIENCE_MISMATCH",
    );
    expectVerificationError(
      () => verifyServiceCredential(issueRelayToken(), shiyanVerifier()),
      "AUDIENCE_MISMATCH",
    );
  });

  it("rejects unexpected or malformed scope and Relay context", () => {
    for (const claims of [
      shiyanClaims({ scope: [RELAY_TRANSPORT_SCOPE] }),
      shiyanClaims({ scope: [SHIYAN_AUTHENTICATE_SCOPE, RELAY_TRANSPORT_SCOPE] }),
      shiyanClaims({ scope: [] }),
      shiyanClaims({ scope: undefined }),
      shiyanClaims({ aud: CLOUD_RELAY_TRANSPORT_AUDIENCE }),
    ]) {
      expectVerificationError(
        () => verifyServiceCredential(signRawToken(header(), claims, privateKey), shiyanVerifier()),
        "INVALID_CLAIMS",
      );
    }

    for (const claims of [
      relayClaims({ relay: undefined }),
      relayClaims({ relay: { room: "room-7f3a", role: "owner" } }),
      relayClaims({ relay: { room: "room 7f3a", role: "client" } }),
      relayClaims({ remoteToolScope: "terminal" }),
      relayClaims({ scope: [RELAY_TRANSPORT_SCOPE, "remote:terminal"] }),
    ]) {
      expectVerificationError(
        () => verifyServiceCredential(signRawToken(header(), claims, privateKey), relayVerifier()),
        "INVALID_CLAIMS",
      );
    }
  });

  it("rejects malformed headers and unsigned or unsupported algorithms", () => {
    const payload = shiyanClaims();
    for (const token of [
      "not-a-jwt",
      "a.b",
      "a.b.c.d",
      signRawToken(header({ alg: "none" }), payload, privateKey),
      signRawToken(header({ alg: "HS256" }), payload, privateKey),
      signRawToken(header({ typ: "JWS" }), payload, privateKey),
      signRawToken(header({ kid: "" }), payload, privateKey),
      signRawToken({ alg: "EdDSA", typ: "JWT" }, payload, privateKey),
    ]) {
      expectVerificationError(
        () => verifyServiceCredential(token, shiyanVerifier()),
        token === "not-a-jwt" || token === "a.b" || token === "a.b.c.d"
          ? "MALFORMED_TOKEN"
          : "INVALID_HEADER",
      );
    }
  });

  it("rejects unknown keys and invalid signatures without trusting token metadata", () => {
    expectVerificationError(
      () =>
        verifyServiceCredential(
          signRawToken(header({ kid: "untrusted-key" }), shiyanClaims(), privateKey),
          shiyanVerifier(),
        ),
      "UNKNOWN_KEY",
    );

    expectVerificationError(
      () =>
        verifyServiceCredential(
          signRawToken(header(), shiyanClaims(), otherKeys.privateKey),
          shiyanVerifier(),
        ),
      "INVALID_SIGNATURE",
    );

    const valid = issueShiyanToken();
    const [headerSegment, , signatureSegment] = valid.split(".");
    const modifiedPayload = Buffer.from(
      JSON.stringify(shiyanClaims({ sub: "another-account" })),
      "utf8",
    ).toString("base64url");
    expectVerificationError(
      () =>
        verifyServiceCredential(
          `${headerSegment}.${modifiedPayload}.${signatureSegment}`,
          shiyanVerifier(),
        ),
      "INVALID_SIGNATURE",
    );
  });

  it("selects only the trusted key matching the token key id", () => {
    const trustedKeys = new Map([
      [KEY_ID, publicKey],
      ["retiring-key", otherKeys.publicKey],
    ]);

    expect(
      verifyServiceCredential(issueShiyanToken(), shiyanVerifier({ publicKeys: trustedKeys })).keyId,
    ).toBe(KEY_ID);

    expectVerificationError(
      () =>
        verifyServiceCredential(
          signRawToken(header({ kid: "retiring-key" }), shiyanClaims(), privateKey),
          shiyanVerifier({ publicKeys: trustedKeys }),
        ),
      "INVALID_SIGNATURE",
    );
  });

  it("rejects untrusted issuers and invalid subject or device claims", () => {
    expectVerificationError(
      () =>
        verifyServiceCredential(
          signRawToken(header(), shiyanClaims({ iss: "mira:other-issuer" }), privateKey),
          shiyanVerifier(),
        ),
      "ISSUER_MISMATCH",
    );

    for (const claims of [
      shiyanClaims({ sub: "" }),
      shiyanClaims({ sub: undefined }),
      shiyanClaims({ device_id: "" }),
      shiyanClaims({ device_id: undefined }),
      shiyanClaims({ iat: undefined }),
      shiyanClaims({ nbf: FIXED_NOW_SECONDS + 1, exp: FIXED_NOW_SECONDS }),
    ]) {
      expectVerificationError(
        () => verifyServiceCredential(signRawToken(header(), claims, privateKey), shiyanVerifier()),
        "INVALID_CLAIMS",
      );
    }
  });

  it("fails closed on expiry, early use, future issuance and excessive lifetime", () => {
    expectVerificationError(
      () =>
        verifyServiceCredential(
          issueShiyanToken(),
          shiyanVerifier({ now: () => new Date((FIXED_NOW_SECONDS + 301) * 1000) }),
        ),
      "EXPIRED",
    );

    expectVerificationError(
      () =>
        verifyServiceCredential(
          signRawToken(
            header(),
            shiyanClaims({
              nbf: FIXED_NOW_SECONDS + 30,
              exp: FIXED_NOW_SECONDS + 330,
            }),
            privateKey,
          ),
          shiyanVerifier(),
        ),
      "NOT_YET_VALID",
    );

    expectVerificationError(
      () =>
        verifyServiceCredential(
          signRawToken(
            header(),
            shiyanClaims({
              iat: FIXED_NOW_SECONDS + 30,
              nbf: FIXED_NOW_SECONDS + 30,
              exp: FIXED_NOW_SECONDS + 330,
            }),
            privateKey,
          ),
          shiyanVerifier(),
        ),
      "IAT_IN_FUTURE",
    );

    const longLived = issueServiceCredential(
      { privateKey, keyId: KEY_ID, now: () => FIXED_NOW, ttlSeconds: 600 },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      },
    );
    expectVerificationError(
      () => verifyServiceCredential(longLived, shiyanVerifier({ maxTtlSeconds: 300 })),
      "TTL_EXCEEDED",
    );
  });

  it("allows bounded clock skew but still rejects claims outside it", () => {
    const expired = verifyServiceCredential(
      issueShiyanToken(),
      shiyanVerifier({
        now: () => new Date((FIXED_NOW_SECONDS + 301) * 1000),
        clockSkewSeconds: 5,
      }),
    );
    expect(expired.claims.sub).toBe(ACCOUNT_ID);

    expectVerificationError(
      () =>
        verifyServiceCredential(
          issueShiyanToken(),
          shiyanVerifier({
            now: () => new Date((FIXED_NOW_SECONDS + 306) * 1000),
            clockSkewSeconds: 5,
          }),
        ),
      "EXPIRED",
    );
  });

  it("rejects unsafe verifier configurations explicitly", () => {
    const token = issueShiyanToken();

    expectVerificationError(
      () => verifyServiceCredential(token, shiyanVerifier({ publicKeys: new Map() })),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () => verifyServiceCredential(token, shiyanVerifier({ issuer: "" })),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () =>
        verifyServiceCredential(
          token,
          shiyanVerifier({
            audience: "mira:unknown" as ServiceCredentialVerifierConfig["audience"],
          }),
        ),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () => verifyServiceCredential(token, shiyanVerifier({ maxTtlSeconds: 601 })),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () => verifyServiceCredential(token, shiyanVerifier({ clockSkewSeconds: 61 })),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () =>
        verifyServiceCredential(
          token,
          shiyanVerifier({ expectedRelay: { room: "room-1", role: "client" } }),
        ),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () =>
        verifyServiceCredential(
          issueRelayToken(),
          relayVerifier({ expectedRelay: { room: "room-1", role: "owner" as "client" } }),
        ),
      "INVALID_VERIFIER_CONFIG",
    );

    // A Relay ticket must never be accepted as connection eligibility
    // without verifying the actual requested room and peer role.
    const relayWithoutConnectionContext = relayVerifier();
    delete relayWithoutConnectionContext.expectedRelay;
    expectVerificationError(
      () => verifyServiceCredential(issueRelayToken(), relayWithoutConnectionContext),
      "INVALID_VERIFIER_CONFIG",
    );

    // An invalid injected clock must not turn every expiry comparison into false.
    expectVerificationError(
      () => verifyServiceCredential(issueShiyanToken(), shiyanVerifier({ now: () => new Date(NaN) })),
      "INVALID_VERIFIER_CONFIG",
    );
    expectVerificationError(
      () => verifyServiceCredential(issueRelayToken(), relayVerifier({ now: () => new Date(NaN) })),
      "INVALID_VERIFIER_CONFIG",
    );
  });
});

describe("Who You credential verification contract", () => {
  const confirmation = {
    actor: "user" as const,
    draft_id: "dr_0123456789abcdef",
    draft_version: 7,
    content_hash: "a".repeat(64),
    nonce: "nonce-0123456789abcdef",
  };

  function whoYouClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: ACCOUNT_ID,
      device_id: DEVICE_ID,
      aud: CLOUD_WHO_YOU_AUDIENCE,
      scope: [WHOYOU_READ_SCOPE],
      consumer_id: ACCOUNT_ID,
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + 300,
      ...overrides,
    };
  }

  function whoYouVerifier(): ServiceCredentialVerifierConfig {
    return {
      issuer: SERVICE_CREDENTIAL_ISSUER,
      audience: CLOUD_WHO_YOU_AUDIENCE,
      publicKeys: new Map([[KEY_ID, publicKey]]),
      now: () => FIXED_NOW,
    };
  }

  it("verifies a read credential and returns the Who You consumer", () => {
    const token = issueServiceCredential(
      { privateKey, keyId: KEY_ID, now: () => FIXED_NOW },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scope: [WHOYOU_READ_SCOPE],
        consumerId: ACCOUNT_ID,
      },
    );

    const verified = verifyServiceCredential(token, whoYouVerifier());
    expect(verified.claims).toMatchObject({
      aud: CLOUD_WHO_YOU_AUDIENCE,
      consumer_id: ACCOUNT_ID,
      scope: [WHOYOU_READ_SCOPE],
    });
    expect("confirmation" in verified.claims).toBe(false);
  });

  it("verifies a send credential bound to one draft revision", () => {
    const token = issueServiceCredential(
      { privateKey, keyId: KEY_ID, now: () => FIXED_NOW },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scope: [WHOYOU_MAIL_SEND_SCOPE],
        consumerId: ACCOUNT_ID,
        confirmation,
      },
    );

    const verified = verifyServiceCredential(token, whoYouVerifier());
    expect(verified.claims).toMatchObject({
      scope: [WHOYOU_MAIL_SEND_SCOPE],
      confirmation,
    });
  });

  it("keeps Who You audience non-interchangeable with Shiyan", () => {
    const token = issueServiceCredential(
      { privateKey, keyId: KEY_ID, now: () => FIXED_NOW },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scope: [WHOYOU_READ_SCOPE],
        consumerId: ACCOUNT_ID,
      },
    );

    expectVerificationError(
      () => verifyServiceCredential(token, shiyanVerifier()),
      "AUDIENCE_MISMATCH",
    );
    expectVerificationError(
      () => verifyServiceCredential(issueShiyanToken(), whoYouVerifier()),
      "AUDIENCE_MISMATCH",
    );
  });

  it("rejects broken draft binding and consumer claims", () => {
    for (const claims of [
      whoYouClaims({ consumer_id: "account-0002" }),
      whoYouClaims({ consumer_id: undefined }),
      whoYouClaims({ scope: [WHOYOU_MAIL_SEND_SCOPE] }),
      whoYouClaims({
        confirmation: { ...confirmation, draft_version: 0 },
      }),
      whoYouClaims({
        confirmation: { ...confirmation, content_hash: "A".repeat(64) },
      }),
      whoYouClaims({
        confirmation: { ...confirmation, nonce: "short" },
      }),
    ]) {
      expectVerificationError(
        () => verifyServiceCredential(signRawToken(header(), claims, privateKey), whoYouVerifier()),
        "INVALID_CLAIMS",
      );
    }
  });
});
