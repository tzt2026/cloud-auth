import { readFileSync } from "node:fs";
import { loadConfig } from "./config.js";
import { openDatabase } from "./storage/database.js";
import { AuthRepository } from "./auth/auth-repository.js";
import { AuthService, AuthError } from "./auth/auth-service.js";
import { PasswordHasher } from "./security/password.js";
import { LoginGuard } from "./security/login-guard.js";
import { backfillGuanlanRegistrations, listGuanlanRegistrations, retryGuanlanRegistration, deliverGuanlanRegistrations, createGuanlanRegistrationTransport } from "./guanlan-registration.js";

const [, , command, username] = process.argv;

if (!command || (!username && !['guanlan-backfill','guanlan-status','guanlan-deliver'].includes(command))) {
  printUsageAndExit();
}

const config = loadConfig();
const db = openDatabase({ databasePath: config.databasePath });
const repository = new AuthRepository(db);
const hasher = new PasswordHasher({
  memoryKiB: config.argon2MemoryKiB,
  passes: config.argon2Passes,
  parallelism: config.argon2Parallelism,
  tagLength: 32,
});
const service = new AuthService(
  repository,
  hasher,
  new LoginGuard({
    maxConcurrentHashes: config.passwordMaxConcurrency,
    perUsernamePerMinute: config.loginPerUsernamePerMinute,
    perIpPerMinute: config.loginPerIpPerMinute,
  }),
  { sessionTtlSeconds: config.sessionTtlSeconds },
);

try {
  switch (command) {
    case "provision": {
      const password = readPasswordFromStdin();
      const account = await service.provisionAccount(username, password);
      console.log(JSON.stringify({ id: account.id, username: account.username, allowed: account.isAllowed }));
      break;
    }
    case "reset-password":
      await service.resetPassword(username, readPasswordFromStdin());
      console.log(JSON.stringify({ username, passwordReset: true, sessionsRevoked: true }));
      break;
    case "allow":
      service.setAllowed(username, true);
      console.log(JSON.stringify({ username, allowed: true }));
      break;
    case "deny":
      service.setAllowed(username, false);
      console.log(JSON.stringify({ username, allowed: false, sessionsRevoked: true }));
      break;
    case "enable":
      service.setDisabled(username, false);
      console.log(JSON.stringify({ username, disabled: false }));
      break;
    case "disable":
      service.setDisabled(username, true);
      console.log(JSON.stringify({ username, disabled: true, sessionsRevoked: true }));
      break;
    case "guanlan-backfill": {
      const enqueued = backfillGuanlanRegistrations(db, new Date().toISOString());
      console.log(JSON.stringify({ enqueued, registrations: listGuanlanRegistrations(db).length }));
      break;
    }
    case "guanlan-status": {
      const account = username ? repository.findAccountByUsername(username.trim().normalize("NFKC").toLowerCase()) : null;
      console.log(JSON.stringify({ registrations: username && !account ? [] : listGuanlanRegistrations(db, account?.id) }));
      break;
    }
    case "guanlan-retry": {
      const account = repository.findAccountByUsername(username.trim().normalize("NFKC").toLowerCase());
      const requeued = account ? Number(retryGuanlanRegistration(db, account.id, new Date().toISOString())) : 0;
      console.log(JSON.stringify({ requeued }));
      break;
    }
    case "guanlan-deliver": {
      const endpoint = process.env.MIRA_GUANLAN_REGISTRATION_URL;
      const secret = process.env.MIRA_GUANLAN_REGISTRATION_SECRET;
      if (!endpoint || !secret) throw new Error("Guanlan registration delivery not configured");
      const result = await deliverGuanlanRegistrations(db, createGuanlanRegistrationTransport(endpoint, secret));
      console.log(JSON.stringify(result));
      if (result.failed) process.exitCode = 1;
      break;
    }
    default:
      printUsageAndExit();
  }
} catch (error) {
  if (error instanceof AuthError) {
    console.error(`${error.code}: ${error.message}`);
    process.exitCode = 2;
  } else {
    console.error("Admin operation failed");
    process.exitCode = 1;
  }
} finally {
  db.close();
}

function readPasswordFromStdin(): string {
  if (process.stdin.isTTY) {
    console.error("Password must be provided on stdin; plaintext command-line password arguments are not supported.");
    process.exit(2);
  }
  return readFileSync(0, "utf8");
}

function printUsageAndExit(): never {
  console.error(
    "Usage: pnpm run admin <provision|reset-password|allow|deny|enable|disable|guanlan-backfill|guanlan-status|guanlan-retry|guanlan-deliver> [username]\n" +
      "provision/reset-password read the password from stdin.",
  );
  process.exit(2);
}
