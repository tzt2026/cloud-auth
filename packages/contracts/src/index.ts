import { z } from "zod";
import {
  OAUTH_AUTHORIZATION_CODE_GRANT_TYPE,
  oauthAuthorizationCodeSchema,
  oauthClientIdSchema,
  oauthPkceCodeVerifierSchema,
  oauthRedirectUriSchema,
} from "./oauth.js";

export {
  FIRST_PARTY_OAUTH_CLIENTS,
  MIRA_DESKTOP_OAUTH_CLIENT_ID,
  MIRA_DESKTOP_OAUTH_REDIRECT_URI,
  MIRA_MOBILE_OAUTH_CLIENT_ID,
  MIRA_MOBILE_OAUTH_REDIRECT_URI,
  OAUTH_AUTHORIZATION_CODE_DEFAULT_TTL_SECONDS,
  OAUTH_AUTHORIZATION_CODE_GRANT_TYPE,
  OAUTH_AUTHORIZATION_CODE_MAX_TTL_SECONDS,
  OAUTH_AUTHORIZATION_CODE_RESPONSE_TYPE,
  OAUTH_PKCE_S256_METHOD,
  findFirstPartyOAuthClient,
  isRegisteredOAuthRedirectUri,
  oauthApiErrorCodeSchema,
  oauthApiErrorEnvelopeSchema,
  oauthAuthorizationCallbackErrorSchema,
  oauthAuthorizationCallbackSchema,
  oauthAuthorizationCodeSchema,
  oauthAuthorizationErrorCallbackSchema,
  oauthAuthorizationRequestSchema,
  oauthClientIdSchema,
  oauthCodeChallengeMethodSchema,
  oauthPkceCodeChallengeSchema,
  oauthPkceCodeVerifierSchema,
  oauthRedirectUriSchema,
  oauthStateSchema,
} from "./oauth.js";

export type {
  FirstPartyOAuthClient,
  OAuthApiErrorCode,
  OAuthApiErrorEnvelope,
  OAuthAuthorizationCallback,
  OAuthAuthorizationCallbackError,
  OAuthAuthorizationErrorCallback,
  OAuthAuthorizationRequest,
  OAuthClientId,
} from "./oauth.js";

export {
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  CLOUD_WHO_YOU_AUDIENCE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  RELAY_TRANSPORT_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  SHIYAN_AUTHENTICATE_SCOPE,
  WHOYOU_MAIL_SEND_SCOPE,
  WHOYOU_MAIL_WRITE_SCOPE,
  WHOYOU_READ_SCOPE,
  guanlanConsumerIdSchema,
  guanlanRequestedScopesSchema,
  guanlanScopeClaimsSchema,
  guanlanServiceCredentialClaimsSchema,
  issuedServiceCredentialSchema,
  relayConnectionRoleSchema,
  relayRoomSchema,
  relayServiceCredentialClaimsSchema,
  relayTicketContextSchema,
  serviceCredentialAudienceSchema,
  serviceCredentialClaimsSchema,
  serviceCredentialErrorCodeSchema,
  serviceCredentialErrorEnvelopeSchema,
  serviceCredentialJwksSchema,
  serviceCredentialJwtHeaderSchema,
  serviceCredentialKeyIdSchema,
  serviceCredentialPublicJwkSchema,
  serviceCredentialRequestSchema,
  serviceCredentialScopeSchema,
  shiyanServiceCredentialClaimsSchema,
  whoYouConfirmationSchema,
  whoYouConsumerIdSchema,
  whoYouContentHashSchema,
  whoYouDraftIdSchema,
  whoYouDraftVersionSchema,
  whoYouRequestedScopesSchema,
  whoYouScopeClaimsSchema,
  whoYouServiceCredentialClaimsSchema,
  whoYouServiceCredentialRequestSchema,
} from "./service-credential.js";

export type {
  GuanlanServiceCredentialClaims,
  IssuedServiceCredential,
  RelayConnectionRole,
  RelayServiceCredentialClaims,
  RelayTicketContext,
  ServiceCredentialAudience,
  ServiceCredentialClaims,
  ServiceCredentialErrorCode,
  ServiceCredentialErrorEnvelope,
  ServiceCredentialJwks,
  ServiceCredentialJwtHeader,
  ServiceCredentialPublicJwk,
  ServiceCredentialRequest,
  ServiceCredentialScope,
  ShiyanServiceCredentialClaims,
  WhoYouConfirmation,
  WhoYouServiceCredentialClaims,
} from "./service-credential.js";

export {
  desktopHostAvailabilitySchema,
  desktopHostListResponseSchema,
  desktopHostSchema,
  hostErrorCodeSchema,
  hostErrorEnvelopeSchema,
  registerHostRequestSchema,
} from "./host.js";

export type {
  DesktopHost,
  DesktopHostAvailability,
  DesktopHostListResponse,
  HostErrorCode,
  HostErrorEnvelope,
  RegisterHostRequest,
} from "./host.js";

export {
  REMOTE_DEVICE_SCOPES,
  canonicalRemoteDeviceScopes,
  hostGrantEntrySchema,
  hostGrantManagementEntrySchema,
  hostGrantManagementListResponseSchema,
  hostGrantErrorCodeSchema,
  hostGrantErrorEnvelopeSchema,
  hostGrantPolicyResponseSchema,
  hostGrantSnapshotSchema,
  hostMobileGrantMutationResponseSchema,
  hostMobileGrantSchema,
  hostMobileGrantStatusSchema,
  remoteDeviceScopeSchema,
  setHostGrantPolicyRequestSchema,
  updateHostMobileGrantRequestSchema,
} from "./host-grant.js";

export type {
  HostGrantEntry,
  HostGrantManagementEntry,
  HostGrantManagementListResponse,
  HostGrantErrorCode,
  HostGrantErrorEnvelope,
  HostGrantPolicyResponse,
  HostGrantSnapshot,
  HostMobileGrant,
  HostMobileGrantMutationResponse,
  HostMobileGrantStatus,
  RemoteDeviceScope,
  SetHostGrantPolicyRequest,
  UpdateHostMobileGrantRequest,
} from "./host-grant.js";

export const accountIdentitySchema = z
  .object({
    id: z.string().min(1),
    username: z.string().min(1),
  })
  .strict();

export const devicePlatformSchema = z.enum(["desktop", "mobile"]);

const installationIdPattern =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

const installationIdSchema = z
  .string()
  .regex(installationIdPattern, "installationId must be a randomly generated UUIDv4");

/**
 * First-party token exchange. Standard OAuth fields use snake_case because the
 * endpoint consumes application/x-www-form-urlencoded. The installation
 * identity is an input identifier only: ownership, platform and revocation are
 * resolved server-side from the authorized account, never trusted from the
 * client. Unknown or repeated parameters are rejected by the route.
 */
export const oauthTokenRequestSchema = z
  .object({
    grant_type: z.literal(OAUTH_AUTHORIZATION_CODE_GRANT_TYPE),
    client_id: oauthClientIdSchema,
    code: oauthAuthorizationCodeSchema,
    redirect_uri: oauthRedirectUriSchema,
    code_verifier: oauthPkceCodeVerifierSchema,
    installation_id: installationIdSchema,
    platform: devicePlatformSchema,
  })
  .strict();

export type OAuthTokenRequest = z.infer<typeof oauthTokenRequestSchema>;

export const deviceLoginContextSchema = z
  .object({
    installationId: installationIdSchema,
    platform: devicePlatformSchema,
  })
  .strict();

export const loginRequestSchema = z
  .object({
    username: z.string().min(1).max(128),
    password: z.string().min(1).max(256),
    device: deviceLoginContextSchema.optional(),
  })
  .strict();

export const changePasswordRequestSchema = z
  .object({
    currentPassword: z.string().min(1).max(256),
    newPassword: z.string().min(1).max(256),
  })
  .strict();

export const cloudSessionSchema = z
  .object({
    account: accountIdentitySchema,
    expiresAt: z.iso.datetime(),
  })
  .strict();

export const issuedCloudSessionSchema = cloudSessionSchema
  .extend({
    sessionToken: z.string().min(1),
  })
  .strict();

export const deviceIdSchema = z.uuid();

export const registerDeviceRequestSchema = z
  .object({
    installationId: installationIdSchema,
    platform: devicePlatformSchema,
    clientName: z.string().min(1).max(80).regex(/\S/, "clientName must not be blank").optional(),
    clientVersion: z
      .string()
      .min(1)
      .max(64)
      .regex(/\S/, "clientVersion must not be blank")
      .optional(),
  })
  .strict();

export const miraDeviceSchema = z
  .object({
    id: z.string().min(1),
    platform: devicePlatformSchema,
    clientName: z.string().min(1).max(80).nullable(),
    clientVersion: z.string().min(1).max(64).nullable(),
    createdAt: z.iso.datetime(),
    lastSeenAt: z.iso.datetime(),
    revokedAt: z.iso.datetime().nullable(),
  })
  .strict();

export const deviceListResponseSchema = z
  .object({
    devices: z.array(miraDeviceSchema),
  })
  .strict();

export const deviceErrorCodeSchema = z.enum([
  "DEVICE_INVALID_REQUEST",
  "DEVICE_NOT_FOUND",
  "DEVICE_REVOKED",
  "DEVICE_PLATFORM_MISMATCH",
  "DEVICE_SESSION_MISMATCH",
  "DEVICE_INTERNAL_ERROR",
]);

export const deviceErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: deviceErrorCodeSchema,
        message: z.string().min(1),
      })
      .strict(),
  })
  .strict();

export const publicAuthErrorCodeSchema = z.enum([
  "AUTH_INVALID_CREDENTIALS",
  "AUTH_INVALID_PASSWORD",
  "AUTH_REAUTH_REQUIRED",
  "AUTH_DEVICE_REJECTED",
  "AUTH_RATE_LIMITED",
  "AUTH_BUSY",
  "AUTH_INTERNAL_ERROR",
]);

export const authErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: publicAuthErrorCodeSchema,
        message: z.string().min(1),
      })
      .strict(),
  })
  .strict();

export const loginRequestJsonSchema = z.toJSONSchema(loginRequestSchema, {
  target: "draft-7",
});

export const changePasswordRequestJsonSchema = z.toJSONSchema(
  changePasswordRequestSchema,
  {
    target: "draft-7",
  },
);

export type AccountIdentity = z.infer<typeof accountIdentitySchema>;
export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type ChangePasswordRequest = z.infer<typeof changePasswordRequestSchema>;
export type CloudSession = z.infer<typeof cloudSessionSchema>;
export type IssuedCloudSession = z.infer<typeof issuedCloudSessionSchema>;
export type DevicePlatform = z.infer<typeof devicePlatformSchema>;
export type DeviceLoginContext = z.infer<typeof deviceLoginContextSchema>;
export type RegisterDeviceRequest = z.infer<typeof registerDeviceRequestSchema>;
export type MiraDevice = z.infer<typeof miraDeviceSchema>;
export type DeviceListResponse = z.infer<typeof deviceListResponseSchema>;
export type DeviceErrorCode = z.infer<typeof deviceErrorCodeSchema>;
export type DeviceErrorEnvelope = z.infer<typeof deviceErrorEnvelopeSchema>;
export type PublicAuthErrorCode = z.infer<typeof publicAuthErrorCodeSchema>;
export type AuthErrorEnvelope = z.infer<typeof authErrorEnvelopeSchema>;
