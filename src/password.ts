import { execSync } from "node:child_process";

/**
 * Master password from VAULT_MASTER_PASSWORD, or the stdout of VAULT_MASTER_PASSWORD_CMD
 * (e.g. `security find-generic-password -s vault-mcp -w`). Both are removed from process.env
 * afterwards so they can't leak into child processes.
 */
export function passwordFromEnv(): string | undefined {
  const direct = process.env.VAULT_MASTER_PASSWORD;
  const cmd = process.env.VAULT_MASTER_PASSWORD_CMD;
  delete process.env.VAULT_MASTER_PASSWORD;
  delete process.env.VAULT_MASTER_PASSWORD_CMD;
  if (direct) return direct;
  if (cmd) {
    const out = execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).replace(/\r?\n$/, "");
    if (out) return out;
  }
  return undefined;
}
