import { KeyObject, createPrivateKey, sign } from "node:crypto";
import {
  SERVICE_CREDENTIAL_ISSUER,
  relayTicketContextSchema,
  serviceCredentialClaimsSchema,
  serviceCredentialJwtHeaderSchema,
  whoYouConfirmationSchema,
  type RelayTicketContext,
  type ServiceCredentialAudience,
  type ServiceCredentialScope,
  type WhoYouConfirmation,
} from "@uichat-mira/cloud-auth-contracts";
import {
  ServiceCredentialIssuanceError,
} from "./errors.js";
import { encodeJsonSegment } from "./jwt.js";

export const DEFAULT_SERVICE_CREDENTIAL_TTL_SECONDS = 300;
export const MAX_SERVICE_CREDENTIAL_TTL_SECONDS = 600;

export type Ed25519PrivateKeyInput = KeyObject | string | Buffer;

export interface ServiceCredentialSignerConfig {
  /** Explicitly injected Ed25519 private key. Never read from the environment. */
  privateKey: Ed25519PrivateKeyInput;
  /** Key identifier carried in the JWT header for future rotation. */
  keyId: string;
  ttlSeconds?: number;
  now?: () => Date;
}

export interface IssueServiceCredentialInput {
  accountId: string;
  deviceId: string;
  audience: ServiceCredentialAudience;
  scope: readonly ServiceCredentialScope[];
  relay?: RelayTicketContext;
  /**
   * Stable Guanlan consumer identity, derived server-side from the verified
   * Cloud Session. Required for the Guanlan audience and rejected for others
   * by the canonical claims schema.
   */
  consumerId?: string;
  /**
   * Who You draft-bound user confirmation. Required for whoyou.mail.send and
   * rejected for every other audience by the canonical claims schema.
   */
  confirmation?: WhoYouConfirmation;
}

function resolvePrivateKey(input: Ed25519PrivateKeyInput): KeyObject {
  let key: KeyObject;
  try {
    key = input instanceof KeyObject ? input : createPrivateKey(input);
  } catch (error) {
    throw new ServiceCredentialIssuanceError(
      "INVALID_SIGNING_KEY",
      `Signing key could not be loaded: ${(error as Error).message}`,
    );
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new ServiceCredentialIssuanceError(
      "INVALID_SIGNING_KEY",
      "Signing key must be an Ed25519 private key",
    );
  }
  return key;
}

function resolveTtl(ttlSeconds: number | undefined): number {
  const ttl = ttlSeconds ?? DEFAULT_SERVICE_CREDENTIAL_TTL_SECONDS;
  if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_SERVICE_CREDENTIAL_TTL_SECONDS) {
    throw new ServiceCredentialIssuanceError(
      "INVALID_TTL",
      `Service credential TTL must be an integer between 1 and ${MAX_SERVICE_CREDENTIAL_TTL_SECONDS} seconds`,
    );
  }
  return ttl;
}

export function issueServiceCredential(
  config: ServiceCredentialSignerConfig,
  input: IssueServiceCredentialInput,
): string {
  const privateKey = resolvePrivateKey(config.privateKey);
  const ttlSeconds = resolveTtl(config.ttlSeconds);

  const headerResult = serviceCredentialJwtHeaderSchema.safeParse({
    alg: "EdDSA",
    typ: "JWT",
    kid: config.keyId,
  });
  if (!headerResult.success) {
    throw new ServiceCredentialIssuanceError("INVALID_KID", "Key ID is not a valid JWT key id");
  }

  if (input.relay !== undefined) {
    if (!relayTicketContextSchema.safeParse(input.relay).success) {
      throw new ServiceCredentialIssuanceError(
        "INVALID_INPUT",
        "Relay ticket context is malformed",
      );
    }
  }

  if (input.confirmation !== undefined) {
    if (!whoYouConfirmationSchema.safeParse(input.confirmation).success) {
      throw new ServiceCredentialIssuanceError(
        "INVALID_INPUT",
        "Who You confirmation is malformed",
      );
    }
  }

  const issuedAt = Math.floor((config.now?.() ?? new Date()).getTime() / 1000);
  const claimsResult = serviceCredentialClaimsSchema.safeParse({
    iss: SERVICE_CREDENTIAL_ISSUER,
    sub: input.accountId,
    device_id: input.deviceId,
    aud: input.audience,
    scope: [...input.scope],
    iat: issuedAt,
    nbf: issuedAt,
    exp: issuedAt + ttlSeconds,
    ...(input.relay === undefined ? {} : { relay: input.relay }),
    ...(input.consumerId === undefined ? {} : { consumer_id: input.consumerId }),
    ...(input.confirmation === undefined ? {} : { confirmation: input.confirmation }),
  });
  if (!claimsResult.success) {
    throw new ServiceCredentialIssuanceError(
      "INVALID_INPUT",
      "Service credential input does not satisfy the canonical claims contract",
    );
  }

  const signingInput = `${encodeJsonSegment(headerResult.data)}.${encodeJsonSegment(
    claimsResult.data,
  )}`;
  const signature = sign(null, Buffer.from(signingInput, "ascii"), privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}
