import type { FastifyRequest } from "fastify";
import { AuthError } from "../auth/auth-service.js";

const BEARER_SCHEME = "Bearer";
const WHITESPACE = /\s/;
/** `.` in the original pattern excluded line terminators; keep that rejection. */
const LINE_TERMINATOR = /[\n\r\u2028\u2029]/;

/**
 * Equivalent to `/^Bearer\s+(.+)$/i`, written so the scan stays linear.
 *
 * That pattern overlaps on whitespace — `\s+` and `.+` can both consume it —
 * which is what SonarCloud flagged as super-linear. This version matches the
 * scheme by length, walks the separator run once, and slices the token, while
 * preserving the regex's accept/reject set, including its backtracking quirk:
 * when the separator run reaches the end of the header, `\s+` gives one
 * whitespace character back so `.+` can match, which only works when the run is
 * at least two characters long.
 */
function parseBearerToken(authorization: string): string | null {
  if (authorization.slice(0, BEARER_SCHEME.length).toLowerCase() !== BEARER_SCHEME.toLowerCase()) {
    return null;
  }

  const separatorStart = BEARER_SCHEME.length;
  let cursor = separatorStart;
  while (cursor < authorization.length && WHITESPACE.test(authorization[cursor]!)) {
    cursor += 1;
  }

  const separatorLength = cursor - separatorStart;
  if (separatorLength === 0) return null;

  // The run continues to the end of the header, so the token has to come from
  // inside the run: only a run of two or more leaves one character for `.+`.
  const token =
    cursor === authorization.length
      ? separatorLength >= 2
        ? authorization.slice(-1)
        : null
      : authorization.slice(cursor);

  if (token === null || token === "") return null;
  if (LINE_TERMINATOR.test(token)) return null;
  return token;
}

export function readBearerToken(request: FastifyRequest): string {
  const authorization = request.headers.authorization;
  if (!authorization) throw new AuthError("AUTH_REAUTH_REQUIRED", 401, "Re-authentication is required");

  const token = parseBearerToken(authorization);
  if (!token) throw new AuthError("AUTH_REAUTH_REQUIRED", 401, "Re-authentication is required");
  return token;
}
