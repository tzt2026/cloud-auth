import { argon2, randomBytes, timingSafeEqual } from "node:crypto";

export interface Argon2Policy {
  memoryKiB: number;
  passes: number;
  parallelism: number;
  tagLength: number;
}

export const DEFAULT_ARGON2_POLICY: Argon2Policy = {
  memoryKiB: 19_456,
  passes: 2,
  parallelism: 1,
  tagLength: 32,
};

const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$XPGuKe6+xa9Dti2Vvk8S9A$//+HrEqkvmOC23Rm44RUURxmigtLyjXdoJ9P0w3Cu3U";

const MIN_PASSWORD_CODE_POINTS = 15;
const MAX_PASSWORD_CODE_POINTS = 256;

function runArgon2(message: Buffer, salt: Buffer, policy: Argon2Policy): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2(
      "argon2id",
      {
        message,
        nonce: salt,
        parallelism: policy.parallelism,
        tagLength: policy.tagLength,
        memory: policy.memoryKiB,
        passes: policy.passes,
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      },
    );
  });
}

export function validatePassword(password: string): void {
  const length = [...password].length;
  if (length < MIN_PASSWORD_CODE_POINTS) {
    throw new Error(`Password must contain at least ${MIN_PASSWORD_CODE_POINTS} characters`);
  }
  if (length > MAX_PASSWORD_CODE_POINTS) {
    throw new Error(`Password must contain at most ${MAX_PASSWORD_CODE_POINTS} characters`);
  }
}

export class PasswordHasher {
  constructor(readonly policy: Argon2Policy = DEFAULT_ARGON2_POLICY) {}

  async hash(password: string): Promise<string> {
    validatePassword(password);
    const salt = randomBytes(16);
    const digest = await runArgon2(Buffer.from(password, "utf8"), salt, this.policy);
    return encodePasswordHash(this.policy, salt, digest);
  }

  async verify(password: string, encodedHash: string): Promise<boolean> {
    const parsed = parsePasswordHash(encodedHash);
    const digest = await runArgon2(Buffer.from(password, "utf8"), parsed.salt, parsed.policy);
    return digest.length === parsed.digest.length && timingSafeEqual(digest, parsed.digest);
  }

  async burnUnknownPassword(password: string): Promise<void> {
    await this.verify(password, DUMMY_PASSWORD_HASH);
  }
}

/**
 * Base64 padding is only ever trailing, so trimming it by scanning from the end
 * is equivalent to `.replace(/=+$/, "")` — the `=+` there is the overlapping
 * quantifier SonarCloud flags as super-linear.
 */
function stripBase64Padding(encoded: string): string {
  let end = encoded.length;
  while (end > 0 && encoded[end - 1] === "=") end -= 1;
  return encoded.slice(0, end);
}

function encodePasswordHash(policy: Argon2Policy, salt: Buffer, digest: Buffer): string {
  return [
    "$argon2id",
    "$v=19",
    `$m=${policy.memoryKiB},t=${policy.passes},p=${policy.parallelism}`,
    `$${stripBase64Padding(salt.toString("base64"))}`,
    `$${stripBase64Padding(digest.toString("base64"))}`,
  ].join("");
}

function parsePasswordHash(encodedHash: string): { policy: Argon2Policy; salt: Buffer; digest: Buffer } {
  const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(
    encodedHash,
  );
  if (!match) throw new Error("Unsupported password hash format");

  const memory = match[1]!;
  const passes = match[2]!;
  const parallelism = match[3]!;
  const salt = match[4]!;
  const digest = match[5]!;

  return {
    policy: {
      memoryKiB: Number(memory),
      passes: Number(passes),
      parallelism: Number(parallelism),
      tagLength: Buffer.from(digest, "base64").length,
    },
    salt: Buffer.from(salt, "base64"),
    digest: Buffer.from(digest, "base64"),
  };
}

export function describePasswordPolicy(): {
  minCharacters: number;
  maxCharacters: number;
  argon2: Argon2Policy;
} {
  return {
    minCharacters: MIN_PASSWORD_CODE_POINTS,
    maxCharacters: MAX_PASSWORD_CODE_POINTS,
    argon2: { ...DEFAULT_ARGON2_POLICY },
  };
}
