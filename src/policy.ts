/**
 * Rules enforced by the server itself (not just described to the model):
 *  - allowed hosts per service: secrets may only be sent to listed hosts
 *  - use budget: repeated use of a secret needs the user's approval
 *  - lock on rejected login: a 401 locks the credential until re-entered or unlocked
 */

/** Uses of the same secret field allowed within USE_WINDOW_MIN before the user must approve. */
export const USE_BUDGET = 5;
export const USE_WINDOW_MIN = 10;
/** After the user clicks Allow, further uses are free for this long. */
export const APPROVAL_GRACE_MIN = 30;

/** Fields whose repeated use counts against the budget (logins / tokens). */
export const isSecretField = (name: string) => /pass|secret|token|key|pin|otp|pwd/i.test(name);

/** Normalise a host: lower-case, no port, no trailing dot. */
export function normHost(host: string): string {
  return host.trim().toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
}

/** Exact match, or wildcard "*.example.com" (subdomains only, not example.com itself). */
export function hostAllowed(host: string, allowed: string[]): boolean {
  const h = normHost(host);
  return allowed.some((a) => {
    const p = normHost(a);
    if (p.startsWith("*.")) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
    return h === p;
  });
}

/**
 * Best-effort list of hosts a shell command talks to: URLs (http/https/ws/postgres/…),
 * user@host for ssh/scp, and -h/--host/-H host flags (psql, mysql, redis-cli, …).
 */
export function extractHosts(command: string): string[] {
  const hosts = new Set<string>();
  for (const m of command.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/(?:[^@\s/'"]*@)?([a-z0-9.-]+\.[a-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/gi)) {
    hosts.add(normHost(m[1]));
  }
  for (const m of command.matchAll(/(?:^|\s)(?:-h|--host(?:=|\s))\s*['"]?([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})/gi)) {
    hosts.add(normHost(m[1]));
  }
  for (const m of command.matchAll(/\b(?:ssh|scp|sftp|rsync)\b[^|;&]*?\s[\w.-]+@([a-z0-9.-]+\.[a-z]{2,})/gi)) {
    hosts.add(normHost(m[1]));
  }
  return [...hosts];
}

export function hostsPolicyError(service: string, allowed: string[], offending: string[]): string {
  return (
    `blocked: secrets of ${service} may only be sent to [${allowed.join(", ")}], but this targets ${offending.join(", ")}. ` +
    `Credentials are never reused across environments. If this host is legitimate, ask the user to add it: cvault service ${service} --allow-host <host>`
  );
}
