import type { z } from "zod";

/**
 * One HTTP transport for every Portal client.
 *
 * `lib/auth/client.ts`, `lib/grants/client.ts` and `lib/dc-control.ts` used to
 * carry their own copy of the same five helpers (fetch + JSON + envelope +
 * bearer headers). Only the *classification* of a failure differs per API, so
 * this module owns the mechanics and the caller owns the policy through
 * `TransportHooks`.
 */

/** A non-2xx response, already read once so the hook can classify it. */
export interface FailedResponse {
  status: number;
  /** Parsed JSON body, or `undefined` when the body was not JSON. */
  body: unknown;
  /**
   * Whether `body` was readable JSON. Proxies and outages return HTML, and the
   * two APIs report that case differently — the hook decides.
   */
  bodyParsed: boolean;
  headers: Headers;
}

export interface TransportHooks {
  /** The request never reached the server (DNS, offline, aborted socket). */
  networkUnavailable(): Error;
  /** A 2xx response whose body could not be read or did not match the schema. */
  malformedResponse(status: number): Error;
  /** A non-2xx response; runs the API-specific status/envelope policy. */
  responseFailed(response: FailedResponse): Error;
}

export interface HttpTransport {
  /** GET/POST returning a JSON body validated by `schema`, expecting HTTP 200. */
  json<T>(path: string, init: RequestInit, schema: z.ZodType<T>): Promise<T>;
  /** A request whose success is a bare status code (204 for auth mutations). */
  empty(path: string, init: RequestInit, expectedStatus: number): Promise<void>;
}

export interface CreateHttpTransportOptions {
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  hooks: TransportHooks;
}

/**
 * Equivalent to `.replace(/\/+$/, "")`, written as a scan from the end so the
 * URL prefix is trimmed without the regex engine backtracking over the run.
 */
function stripTrailingSlashes(baseUrl: string): string {
  let end = baseUrl.length;
  while (end > 0 && baseUrl[end - 1] === "/") end -= 1;
  return baseUrl.slice(0, end);
}

export function createHttpTransport({
  baseUrl = "",
  fetch: fetchOption,
  hooks,
}: CreateHttpTransportOptions): HttpTransport {
  const origin = stripTrailingSlashes(baseUrl);
  const fetchImpl = fetchOption ?? globalThis.fetch.bind(globalThis);

  async function send(path: string, init: RequestInit): Promise<Response> {
    try {
      return await fetchImpl(`${origin}${path}`, init);
    } catch {
      throw hooks.networkUnavailable();
    }
  }

  async function readBody(response: Response): Promise<{ body: unknown; bodyParsed: boolean }> {
    try {
      return { body: await response.json(), bodyParsed: true };
    } catch {
      return { body: undefined, bodyParsed: false };
    }
  }

  async function failed(response: Response): Promise<never> {
    const { body, bodyParsed } = await readBody(response);
    throw hooks.responseFailed({
      status: response.status,
      body,
      bodyParsed,
      headers: response.headers,
    });
  }

  return {
    async json(path, init, schema) {
      const response = await send(path, init);
      if (response.status !== 200) return failed(response);

      const { body, bodyParsed } = await readBody(response);
      if (!bodyParsed) throw hooks.malformedResponse(response.status);

      const parsed = schema.safeParse(body);
      if (!parsed.success) throw hooks.malformedResponse(response.status);
      return parsed.data;
    },

    async empty(path, init, expectedStatus) {
      const response = await send(path, init);
      if (response.status !== expectedStatus) return failed(response);
    },
  };
}

/** The headers every authenticated Portal request sends. */
export function bearerHeaders(sessionToken: string): Record<string, string> {
  return {
    accept: "application/json",
    authorization: `Bearer ${sessionToken}`,
  };
}

/** The same bearer request without a body, for authenticated GET/DELETE. */
export function authenticatedRequest(
  method: "GET" | "DELETE" | "POST",
  sessionToken: string,
): RequestInit {
  return {
    method,
    headers: bearerHeaders(sessionToken),
  };
}
