import {
  MIRA_DESKTOP_OAUTH_CLIENT_ID,
  MIRA_DESKTOP_OAUTH_REDIRECT_URI,
  MIRA_MOBILE_OAUTH_CLIENT_ID,
  MIRA_MOBILE_OAUTH_REDIRECT_URI,
  issuedCloudSessionSchema,
} from "@uichat-mira/cloud-auth-contracts";
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/app.js";
import { HostGrantRepository } from "../../src/grants/host-grant-repository.js";
import { HostGrantService } from "../../src/grants/host-grant-service.js";
import { HostRepository } from "../../src/hosts/host-repository.js";
import { HostService } from "../../src/hosts/host-service.js";
import { OAuthRepository } from "../../src/oauth/oauth-repository.js";
import { OAuthService } from "../../src/oauth/oauth-service.js";
import { GuanlanRegistrationOutboxReadiness } from "../../src/service-credentials/guanlan-space-readiness.js";
import {
  createServiceCredentialKeyRing,
  type ServiceCredentialKeyMaterialConfig,
  type ServiceCredentialKeyRing,
} from "../../src/service-credentials/keyring.js";
import { ServiceCredentialService } from "../../src/service-credentials/service.js";
import { createTestAuth, type TestAuthContext } from "./auth.js";

export interface TestOAuthContext extends TestAuthContext {
  app: FastifyInstance;
  oauthRepository: OAuthRepository;
  oauthService: OAuthService;
  hostRepository: HostRepository;
  hostService: HostService;
  hostGrantRepository: HostGrantRepository;
  hostGrantService: HostGrantService;
  keyRing: ServiceCredentialKeyRing | null;
  serviceCredentialService: ServiceCredentialService | null;
}

export interface TestOAuthOptions {
  codeTtlSeconds?: number;
  sessionTtlSeconds?: number;
  hostLeaseSeconds?: number;
  hostGrantSnapshotTtlSeconds?: number;
  now?: () => Date;
  serviceCredentialKeyMaterial?: ServiceCredentialKeyMaterialConfig | null;
}

const TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const TEST_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const TEST_STATE = "state-0123456789-abcdef";

export interface FirstPartySessionOptions {
  username: string;
  password: string;
  platform?: "desktop" | "mobile";
  installationId?: string;
}

/**
 * Completes the reviewed OPS-016 browser form and OPS-017 token exchange
 * through Fastify inject. This is the only way tests obtain a Host-eligible
 * Desktop Cloud Session.
 */
export async function createFirstPartySession(
  context: TestOAuthContext,
  options: FirstPartySessionOptions,
) {
  const desktop = (options.platform ?? "desktop") === "desktop";
  const clientId = desktop ? MIRA_DESKTOP_OAUTH_CLIENT_ID : MIRA_MOBILE_OAUTH_CLIENT_ID;
  const redirectUri = desktop
    ? MIRA_DESKTOP_OAUTH_REDIRECT_URI
    : MIRA_MOBILE_OAUTH_REDIRECT_URI;
  const parameters = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: TEST_STATE,
    code_challenge: TEST_CODE_CHALLENGE,
    code_challenge_method: "S256",
  });
  const authorizationUrl = "/v1/oauth/authorize?" + parameters.toString();

  const page = await context.app.inject({ method: "GET", url: authorizationUrl });
  if (page.statusCode !== 200) {
    throw new Error(`Authorization form failed with ${page.statusCode}`);
  }
  const csrfCookie = String(page.headers["set-cookie"]).split(";")[0]!;
  parameters.set("csrf_token", csrfCookie.split("=")[1]!);
  parameters.set("username", options.username);
  parameters.set("password", options.password);

  const authorized = await context.app.inject({
    method: "POST",
    url: "/v1/oauth/authorize",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: csrfCookie,
    },
    payload: parameters.toString(),
  });
  if (authorized.statusCode !== 303) {
    throw new Error(`Authorization failed with ${authorized.statusCode}`);
  }
  const code = new URL(String(authorized.headers.location)).searchParams.get("code");
  if (!code) throw new Error("Authorization response did not contain a code");

  const exchanged = await context.app.inject({
    method: "POST",
    url: "/v1/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: TEST_CODE_VERIFIER,
      installation_id: options.installationId ?? randomUUID(),
      platform: options.platform ?? "desktop",
    }).toString(),
  });
  if (exchanged.statusCode !== 200) {
    throw new Error(`Token exchange failed with ${exchanged.statusCode}`);
  }
  return issuedCloudSessionSchema.parse(exchanged.json());
}

export function createTestOAuthContext(
  databasePath: string,
  options: TestOAuthOptions = {},
): TestOAuthContext {
  const auth = createTestAuth(databasePath);
  const oauthRepository = new OAuthRepository(auth.db);
  const oauthService = new OAuthService(oauthRepository, auth.service, {
    codeTtlSeconds: options.codeTtlSeconds ?? 300,
    sessionTtlSeconds: options.sessionTtlSeconds ?? 3600,
    now: options.now ?? (() => new Date()),
  });
  const hostRepository = new HostRepository(auth.db);
  const hostService = new HostService(hostRepository, auth.service, {
    leaseTtlSeconds: options.hostLeaseSeconds ?? 120,
    ...(options.now ? { now: options.now } : {}),
  });
  const hostGrantRepository = new HostGrantRepository(auth.db);
  const hostGrantService = new HostGrantService(hostGrantRepository, {
    snapshotTtlSeconds: options.hostGrantSnapshotTtlSeconds ?? 300,
    ...(options.now ? { now: options.now } : {}),
  });
  const hasServiceCredentialConfig = Object.hasOwn(
    options,
    "serviceCredentialKeyMaterial",
  );
  const keyRing = hasServiceCredentialConfig
    ? createServiceCredentialKeyRing(options.serviceCredentialKeyMaterial ?? null)
    : null;
  const serviceCredentialService = hasServiceCredentialConfig
    ? new ServiceCredentialService(
        auth.repository,
        keyRing,
        hostService,
        new GuanlanRegistrationOutboxReadiness(auth.db),
      )
    : null;
  const app = buildApp({
    db: auth.db,
    authService: auth.service,
    deviceService: auth.deviceService,
    hostService,
    hostGrantService,
    oauthService,
    ...(serviceCredentialService ? { serviceCredentialService } : {}),
  });

  return {
    ...auth,
    app,
    oauthRepository,
    oauthService,
    hostRepository,
    hostService,
    hostGrantRepository,
    hostGrantService,
    keyRing,
    serviceCredentialService,
  };
}
