import { z } from "zod";

/**
 * Canonical, deployment-neutral issuer identity for Cloud Auth service
 * credentials. Services must configure this value explicitly when verifying;
 * they must not derive trust from the token's own `iss` claim.
 */
export const SERVICE_CREDENTIAL_ISSUER = "mira:cloud-auth" as const;

export const CLOUD_SHIYAN_AUDIENCE = "mira:cloud-shiyan" as const;
export const CLOUD_RELAY_TRANSPORT_AUDIENCE = "mira:cloud-relay-transport" as const;
/**
 * Mira-internal Guanlan audience. The value is owned by the Guanlan resource
 * verifier (`GUANLAN_SERVICE_AUDIENCE`, cloud-mcp-guanlan `src/mcp/config.ts`);
 * a credential minted for another audience must not be accepted there.
 */
export const CLOUD_GUANLAN_AUDIENCE = "mira:cloud-guanlan" as const;
/**
 * Who You mail-resource audience. Who You verifies this audience offline and
 * never accepts a credential minted for another Mira service.
 */
export const CLOUD_WHO_YOU_AUDIENCE = "mira:who-you" as const;

export const serviceCredentialAudienceSchema = z.enum([
  CLOUD_SHIYAN_AUDIENCE,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_WHO_YOU_AUDIENCE,
]);

export const SHIYAN_AUTHENTICATE_SCOPE = "shiyan:authenticate" as const;
export const RELAY_TRANSPORT_SCOPE = "relay:transport" as const;
/** Read gate of the Guanlan MCP resource; required for every Guanlan credential. */
export const GUANLAN_READ_SCOPE = "guanlan.read" as const;
/** Independent decision-write authority; never implied by read. */
export const GUANLAN_WRITE_SCOPE = "guanlan.write" as const;

/** Who You `/mcp` read gate. */
export const WHOYOU_READ_SCOPE = "whoyou.read" as const;
/** Draft lifecycle write authority; never implied by read. */
export const WHOYOU_MAIL_WRITE_SCOPE = "whoyou.mail.write" as const;
/**
 * Send confirmation authority. It is only issued with a draft-bound
 * confirmation and never grants read or write access on its own.
 */
export const WHOYOU_MAIL_SEND_SCOPE = "whoyou.mail.send" as const;

export const serviceCredentialScopeSchema = z.enum([
  SHIYAN_AUTHENTICATE_SCOPE,
  RELAY_TRANSPORT_SCOPE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  WHOYOU_READ_SCOPE,
  WHOYOU_MAIL_WRITE_SCOPE,
  WHOYOU_MAIL_SEND_SCOPE,
]);

export const serviceCredentialKeyIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9._-]+$/, "kid must be a bounded key identifier");

export const relayConnectionRoleSchema = z.enum(["client", "host"]);

export const relayRoomSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/, "room must be a bounded transport identifier");

/**
 * Transport-only context for a hosted Relay connection ticket. `room` binds the
 * ticket to one relay room and `role` identifies the transport peer role. It
 * cannot encode Host Browser/Terminal/Agent/Thread capabilities.
 */
export const relayTicketContextSchema = z
  .object({
    room: relayRoomSchema,
    role: relayConnectionRoleSchema,
  })
  .strict();

export const serviceCredentialJwtHeaderSchema = z
  .object({
    alg: z.literal("EdDSA"),
    typ: z.literal("JWT"),
    kid: serviceCredentialKeyIdSchema,
  })
  .strict();

const temporalClaimsShape = {
  iat: z.number().int().nonnegative(),
  nbf: z.number().int().nonnegative(),
  exp: z.number().int().nonnegative(),
} as const;

const commonClaimsShape = {
  iss: z.string().min(1).max(256),
  sub: z.string().min(1).max(128),
  device_id: z.string().min(1).max(128),
  ...temporalClaimsShape,
} as const;

type TemporalClaims = { iat: number; nbf: number; exp: number };

function refineTemporalClaims(claims: TemporalClaims, context: z.RefinementCtx): void {
  if (claims.nbf < claims.iat) {
    context.addIssue({
      code: "custom",
      message: "nbf must not precede iat",
      path: ["nbf"],
    });
  }
  if (claims.exp <= claims.nbf) {
    context.addIssue({
      code: "custom",
      message: "exp must be after nbf",
      path: ["exp"],
    });
  }
}

export const shiyanServiceCredentialClaimsSchema = z
  .object({
    ...commonClaimsShape,
    aud: z.literal(CLOUD_SHIYAN_AUDIENCE),
    scope: z.tuple([z.literal(SHIYAN_AUTHENTICATE_SCOPE)]),
  })
  .strict()
  .superRefine(refineTemporalClaims);

export const relayServiceCredentialClaimsSchema = z
  .object({
    ...commonClaimsShape,
    aud: z.literal(CLOUD_RELAY_TRANSPORT_AUDIENCE),
    scope: z.tuple([z.literal(RELAY_TRANSPORT_SCOPE)]),
    relay: relayTicketContextSchema,
  })
  .strict()
  .superRefine(refineTemporalClaims);

export const guanlanConsumerIdSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(
    (value) => value === value.trim(),
    "consumer_id must not have surrounding whitespace",
  );

/**
 * Who You consumer identity. Like Guanlan, one Mira Cloud account is one Who
 * You consumer, so the claim must equal the verified subject.
 */
export const whoYouConsumerIdSchema = guanlanConsumerIdSchema;

/** Who You draft identifier, owned by the Who You mailbox store. */
export const whoYouDraftIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/, "draft_id must be a bounded identifier");

/** Monotonic draft version the user confirmed. */
export const whoYouDraftVersionSchema = z
  .number()
  .int()
  .positive()
  .max(2_147_483_647);

/** Lowercase SHA-256 hex of the confirmed draft content, never the content. */
export const whoYouContentHashSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/, "content_hash must be a lowercase SHA-256 hex digest");

/**
 * Opaque single-use nonce. Cloud Auth only signs it; Who You consumes it
 * atomically before any send side effect.
 */
export const whoYouConfirmationNonceSchema = z
  .string()
  .min(16)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/, "nonce must be a bounded base64url value");

/**
 * A user's confirmation of one exact draft revision. Cloud Auth asserts only
 * that the device-bound account session confirmed this content identity. It
 * does not read, store or authorize Who You drafts or user content.
 */
export const whoYouConfirmationSchema = z
  .object({
    actor: z.literal("user"),
    draft_id: whoYouDraftIdSchema,
    draft_version: whoYouDraftVersionSchema,
    content_hash: whoYouContentHashSchema,
    nonce: whoYouConfirmationNonceSchema,
  })
  .strict();

/**
 * Canonical Who You scope sets. Read admits `/mcp`, mail.write edits drafts,
 * and mail.send is valid only together with a draft-bound confirmation.
 */
export const whoYouScopeClaimsSchema = z.union([
  z.tuple([z.literal(WHOYOU_READ_SCOPE)]),
  z.tuple([z.literal(WHOYOU_READ_SCOPE), z.literal(WHOYOU_MAIL_WRITE_SCOPE)]),
  z.tuple([z.literal(WHOYOU_MAIL_SEND_SCOPE)]),
]);

/**
 * Guanlan scope sets. Read is mandatory because the MCP resource gate rejects
 * credentials without `guanlan.read`; write is additive and explicitly
 * requested, never implied by read. The canonical order is fixed so the signed
 * claims are deterministic.
 */
export const guanlanScopeClaimsSchema = z.union([
  z.tuple([z.literal(GUANLAN_READ_SCOPE)]),
  z.tuple([z.literal(GUANLAN_READ_SCOPE), z.literal(GUANLAN_WRITE_SCOPE)]),
]);

export const guanlanServiceCredentialClaimsSchema = z
  .object({
    ...commonClaimsShape,
    aud: z.literal(CLOUD_GUANLAN_AUDIENCE),
    scope: guanlanScopeClaimsSchema,
    consumer_id: guanlanConsumerIdSchema,
  })
  .strict()
  .refine(
    (claims) => claims.consumer_id === claims.sub,
    "consumer_id must equal sub for a Guanlan credential",
  )
  .superRefine(refineTemporalClaims);

export const whoYouServiceCredentialClaimsSchema = z
  .object({
    ...commonClaimsShape,
    aud: z.literal(CLOUD_WHO_YOU_AUDIENCE),
    scope: whoYouScopeClaimsSchema,
    consumer_id: whoYouConsumerIdSchema,
    confirmation: whoYouConfirmationSchema.optional(),
  })
  .strict()
  .refine(
    (claims) => claims.consumer_id === claims.sub,
    "consumer_id must equal sub for a Who You credential",
  )
  .superRefine((claims, context) => {
    const isSend =
      claims.scope.length === 1 && claims.scope[0] === WHOYOU_MAIL_SEND_SCOPE;
    if (isSend && claims.confirmation === undefined) {
      context.addIssue({
        code: "custom",
        message: "whoyou.mail.send requires a draft-bound confirmation",
        path: ["confirmation"],
      });
    }
    if (!isSend && claims.confirmation !== undefined) {
      context.addIssue({
        code: "custom",
        message: "confirmation is only valid with whoyou.mail.send",
        path: ["scope"],
      });
    }
  })
  .superRefine(refineTemporalClaims);

export const serviceCredentialClaimsSchema = z.discriminatedUnion("aud", [
  shiyanServiceCredentialClaimsSchema,
  relayServiceCredentialClaimsSchema,
  guanlanServiceCredentialClaimsSchema,
  whoYouServiceCredentialClaimsSchema,
]);

/**
 * Requested Guanlan scope set. Only the narrow target service is client-chosen;
 * the account, device, issuer, key id and consumer are derived by Cloud Auth.
 * `guanlan.write` may only be requested together with `guanlan.read`.
 */
export const guanlanRequestedScopesSchema = z
  .array(z.enum([GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE]))
  .min(1)
  .max(2)
  .superRefine((scopes, context) => {
    if (!scopes.includes(GUANLAN_READ_SCOPE)) {
      context.addIssue({
        code: "custom",
        message: "guanlan.read is required",
        path: [],
      });
    }
    if (new Set(scopes).size !== scopes.length) {
      context.addIssue({
        code: "custom",
        message: "requested scopes must not repeat",
        path: [],
      });
    }
  });

/**
 * Issuance request. The client chooses only the narrow target service. Account,
 * device, issuer, key id and business scope are derived by Cloud Auth from the
 * authenticated device-bound Cloud Session.
 */
export const whoYouRequestedScopesSchema = z
  .array(z.enum([WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE]))
  .min(1)
  .max(2)
  .superRefine((scopes, context) => {
    if (!scopes.includes(WHOYOU_READ_SCOPE)) {
      context.addIssue({
        code: "custom",
        message: "whoyou.read is required",
        path: [],
      });
    }
    if (new Set(scopes).size !== scopes.length) {
      context.addIssue({
        code: "custom",
        message: "requested scopes must not repeat",
        path: [],
      });
    }
  });

/**
 * Who You request: either a read/write scope set or one draft-bound send
 * confirmation. Both shapes are mutually exclusive and strictly validated.
 */
export const whoYouServiceCredentialRequestSchema = z
  .object({
    audience: z.literal(CLOUD_WHO_YOU_AUDIENCE),
    scopes: whoYouRequestedScopesSchema.optional(),
    confirmation: whoYouConfirmationSchema.optional(),
  })
  .strict();

const baseServiceCredentialRequestSchema = z.discriminatedUnion("audience", [
  z
    .object({
      audience: z.literal(CLOUD_SHIYAN_AUDIENCE),
    })
    .strict(),
  z
    .object({
      audience: z.literal(CLOUD_RELAY_TRANSPORT_AUDIENCE),
      relay: relayTicketContextSchema,
    })
    .strict(),
  z
    .object({
      audience: z.literal(CLOUD_GUANLAN_AUDIENCE),
      scopes: guanlanRequestedScopesSchema.optional(),
    })
    .strict(),
]);

export const serviceCredentialRequestSchema = z
  .union([baseServiceCredentialRequestSchema, whoYouServiceCredentialRequestSchema])
  .superRefine((request, context) => {
    if (
      request.audience === CLOUD_WHO_YOU_AUDIENCE &&
      request.scopes !== undefined &&
      request.confirmation !== undefined
    ) {
      context.addIssue({
        code: "custom",
        message: "scopes and confirmation are mutually exclusive",
        path: ["confirmation"],
      });
    }
  });

export const issuedServiceCredentialSchema = z
  .object({
    token: z.string().min(1),
    tokenType: z.literal("Bearer"),
    audience: serviceCredentialAudienceSchema,
    expiresAt: z.iso.datetime(),
  })
  .strict();

export const serviceCredentialPublicJwkSchema = z
  .object({
    kty: z.literal("OKP"),
    crv: z.literal("Ed25519"),
    use: z.literal("sig"),
    alg: z.literal("EdDSA"),
    kid: serviceCredentialKeyIdSchema,
    x: z.string().regex(/^[A-Za-z0-9_-]+$/),
  })
  .strict();

export const serviceCredentialJwksSchema = z
  .object({
    keys: z.array(serviceCredentialPublicJwkSchema),
  })
  .strict();

export const serviceCredentialErrorCodeSchema = z.enum([
  "SERVICE_CREDENTIAL_INVALID_REQUEST",
  "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
  "SERVICE_CREDENTIAL_DEVICE_REQUIRED",
  "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
  "SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY",
  "SERVICE_CREDENTIAL_UNAVAILABLE",
  "SERVICE_CREDENTIAL_INTERNAL_ERROR",
]);

export const serviceCredentialErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: serviceCredentialErrorCodeSchema,
        message: z.string().min(1),
      })
      .strict(),
  })
  .strict();

export type ServiceCredentialRequest = z.infer<typeof serviceCredentialRequestSchema>;
export type IssuedServiceCredential = z.infer<typeof issuedServiceCredentialSchema>;
export type ServiceCredentialPublicJwk = z.infer<typeof serviceCredentialPublicJwkSchema>;
export type ServiceCredentialJwks = z.infer<typeof serviceCredentialJwksSchema>;
export type ServiceCredentialErrorCode = z.infer<typeof serviceCredentialErrorCodeSchema>;
export type ServiceCredentialErrorEnvelope = z.infer<
  typeof serviceCredentialErrorEnvelopeSchema
>;
export type ServiceCredentialAudience = z.infer<typeof serviceCredentialAudienceSchema>;
export type ServiceCredentialScope = z.infer<typeof serviceCredentialScopeSchema>;
export type RelayConnectionRole = z.infer<typeof relayConnectionRoleSchema>;
export type RelayTicketContext = z.infer<typeof relayTicketContextSchema>;
export type ServiceCredentialJwtHeader = z.infer<typeof serviceCredentialJwtHeaderSchema>;
export type ShiyanServiceCredentialClaims = z.infer<typeof shiyanServiceCredentialClaimsSchema>;
export type RelayServiceCredentialClaims = z.infer<typeof relayServiceCredentialClaimsSchema>;
export type GuanlanServiceCredentialClaims = z.infer<
  typeof guanlanServiceCredentialClaimsSchema
>;
export type WhoYouConfirmation = z.infer<typeof whoYouConfirmationSchema>;
export type WhoYouServiceCredentialClaims = z.infer<
  typeof whoYouServiceCredentialClaimsSchema
>;
export type ServiceCredentialClaims = z.infer<typeof serviceCredentialClaimsSchema>;
