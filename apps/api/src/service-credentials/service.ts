import {
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_WHO_YOU_AUDIENCE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  RELAY_TRANSPORT_SCOPE,
  SHIYAN_AUTHENTICATE_SCOPE,
  WHOYOU_MAIL_SEND_SCOPE,
  WHOYOU_MAIL_WRITE_SCOPE,
  WHOYOU_READ_SCOPE,
  type IssuedServiceCredential,
  type ServiceCredentialJwks,
  type ServiceCredentialRequest,
  type ServiceCredentialScope,
} from "@uichat-mira/cloud-auth-contracts";
import type { AuthRepository } from "../auth/auth-repository.js";
import { hashSessionSecret, parseSessionToken } from "../security/session-token.js";
import { ServiceCredentialRequestError } from "./errors.js";
import type { GuanlanSpaceReadiness } from "./guanlan-space-readiness.js";
import type { ServiceCredentialKeyRing } from "./keyring.js";
import {
  isRelayTicketAuthorized,
  type RelayRoomOwnership,
} from "./relay-admission.js";
import { issueServiceCredential } from "./signer.js";

export interface RelayRoomOwnershipResolver {
  resolveRoomOwnership(relayRoom: string): RelayRoomOwnership | null;
}

/**
 * The signed scope tuple is derived from the requested set, never copied from
 * the request: Guanlan read-only stays read-only and write is only added when
 * the caller asked for it explicitly.
 */
function scopeForRequest(request: ServiceCredentialRequest): ServiceCredentialScope[] {
  if (request.audience === CLOUD_RELAY_TRANSPORT_AUDIENCE) return [RELAY_TRANSPORT_SCOPE];
  if (request.audience === CLOUD_GUANLAN_AUDIENCE) {
    const requested = request.scopes ?? [GUANLAN_READ_SCOPE];
    return requested.includes(GUANLAN_WRITE_SCOPE)
      ? [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE]
      : [GUANLAN_READ_SCOPE];
  }
  if (request.audience === CLOUD_WHO_YOU_AUDIENCE) {
    // A confirmation is a standalone send authority; it never carries read or
    // write scope, so it cannot be used as a general /mcp bearer.
    if (request.confirmation !== undefined) return [WHOYOU_MAIL_SEND_SCOPE];
    const requested = request.scopes ?? [WHOYOU_READ_SCOPE];
    return requested.includes(WHOYOU_MAIL_WRITE_SCOPE)
      ? [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE]
      : [WHOYOU_READ_SCOPE];
  }
  return [SHIYAN_AUTHENTICATE_SCOPE];
}

export class ServiceCredentialService {
  constructor(
    private readonly repository: AuthRepository,
    private readonly keyRing: ServiceCredentialKeyRing | null,
    private readonly relayRoomOwnership: RelayRoomOwnershipResolver,
    private readonly guanlanSpace: GuanlanSpaceReadiness,
  ) {}

  issue(token: string, request: ServiceCredentialRequest): IssuedServiceCredential {
    const keyRing = this.keyRing;
    if (!keyRing) {
      throw new ServiceCredentialRequestError(
        "SERVICE_CREDENTIAL_UNAVAILABLE",
        503,
        "Service credential issuance is not configured",
      );
    }

    const parsed = parseSessionToken(token);
    if (!parsed) {
      throw new ServiceCredentialRequestError(
        "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
        401,
        "Re-authentication is required",
      );
    }

    const now = new Date();
    const relay =
      request.audience === CLOUD_RELAY_TRANSPORT_AUDIENCE ? request.relay : null;
    const guanlan = request.audience === CLOUD_GUANLAN_AUDIENCE;
    const whoYou = request.audience === CLOUD_WHO_YOU_AUDIENCE;
    const confirmation =
      request.audience === CLOUD_WHO_YOU_AUDIENCE ? request.confirmation : undefined;
    const issued = this.repository.issueWithinActiveDeviceSession(
      parsed.id,
      hashSessionSecret(parsed.secret),
      now.toISOString(),
      ({ accountId, deviceId, devicePlatform }) => {
        if (relay) {
          // This query shares the issuance BEGIN IMMEDIATE transaction, so a
          // Host lease, room binding, or device revoke cannot interleave.
          const ownership = this.relayRoomOwnership.resolveRoomOwnership(relay.room);
          if (
            !isRelayTicketAuthorized(
              relay,
              { accountId, deviceId, devicePlatform },
              ownership,
            )
          ) {
            throw new ServiceCredentialRequestError(
              "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
              403,
              "Relay transport ticket is not authorized for this device",
            );
          }
        }

        if (guanlan) {
          // Fail closed: a disabled/denied account is already rejected by the
          // surrounding authority check, and a missing or non-delivered GLN-012
          // registration must not be treated as permission.
          if (this.guanlanSpace.status(accountId) !== "ready") {
            throw new ServiceCredentialRequestError(
              "SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY",
              409,
              "The account is not registered for the requested service",
            );
          }
        }

        const credential = issueServiceCredential(
          { ...keyRing.signer, now: () => now },
          {
            accountId,
            deviceId,
            audience: request.audience,
            scope: scopeForRequest(request),
            ...(relay ? { relay } : {}),
            // The Guanlan consumer and the Who You consumer are both derived
            // from the verified session, never from the request body. One
            // account is one stable consumer for each service.
            ...(guanlan || whoYou ? { consumerId: accountId } : {}),
            ...(confirmation === undefined ? {} : { confirmation }),
          },
        );
        return {
          token: credential,
          expiresAt: new Date(
            (Math.floor(now.getTime() / 1000) + keyRing.ttlSeconds) * 1000,
          ).toISOString(),
        };
      },
    );

    if (!issued.ok) {
      if (issued.reason === "device_required") {
        throw new ServiceCredentialRequestError(
          "SERVICE_CREDENTIAL_DEVICE_REQUIRED",
          403,
          "A device-bound Mira Cloud Session is required",
        );
      }
      throw new ServiceCredentialRequestError(
        "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
        401,
        "Re-authentication is required",
      );
    }

    return {
      token: issued.value.token,
      tokenType: "Bearer",
      audience: request.audience,
      expiresAt: issued.value.expiresAt,
    };
  }

  getJwks(): ServiceCredentialJwks {
    if (!this.keyRing) {
      throw new ServiceCredentialRequestError(
        "SERVICE_CREDENTIAL_UNAVAILABLE",
        503,
        "Service credential verification keys are not configured",
      );
    }
    return this.keyRing.jwks;
  }
}
