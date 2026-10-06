// ============================================================
// Invitation token utilities — pure, server-side, no Supabase.
//
// Why we hash tokens at rest
// --------------------------
// The DB stores only `account_invitations.token_hash` (SHA-256
// of the random token), never the plaintext. A leaked DB snapshot
// (logs, backups, support exports) therefore can't be used to
// redeem invites — the attacker would need the original token,
// which is returned exactly once at creation time.
//
// Why 32 bytes
// ------------
// 32 bytes of CSPRNG entropy is the standard for opaque session-
// style tokens. base64url-encodes to a 43-char string, fits
// comfortably in a URL, and is well past the practical brute-
// force boundary even with SHA-256 collisions (256 bits >> any
// realistic adversary).
//
// Why base64url (not hex)
// -----------------------
// URL-safe and shorter than hex. `crypto.randomBytes(32).toString
// ('base64url')` lands at 43 characters; hex would be 64.
// ============================================================

import { createHash, randomBytes } from "node:crypto";

/** Default invite link lifetime if the caller doesn't specify. */
export const DEFAULT_INVITE_EXPIRY_DAYS = 7;

/** Hard ceiling on user-supplied `expiresInDays` (1 year). */
export const MAX_INVITE_EXPIRY_DAYS = 365;

export interface GeneratedToken {
  /** Plaintext token — return to the creator ONCE, never persist. */
  token: string;
  /** SHA-256 hex digest of the token. Persist this in the DB. */
  hash: string;
}

/**
 * Generate a fresh invite token + its hash. Call once per invite
 * creation; the plaintext is shown to the admin in the UI and
 * embedded in the shareable link, the hash is stored in
 * `account_invitations.token_hash`.
 */
export function generateInviteToken(): GeneratedToken {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashInviteToken(token) };
}

/**
 * Deterministic SHA-256 of a plaintext token. Used at redeem time
 * to look up the matching `account_invitations` row by `token_hash`.
 * Pure function — same input always produces the same output.
 */
export function hashInviteToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Build the public invite URL the admin will share. The token is
 * carried in the path (not the query) so referrer-policy noise
 * and browser autocomplete don't trip up token preservation.
 *
 * `baseUrl` must NOT have a trailing slash. The function tolerates
 * one anyway (so callers can pass `NEXT_PUBLIC_APP_URL` verbatim
 * without sweating slash hygiene).
 */
export function inviteUrl(token: string, baseUrl: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  return `${trimmed}/join/${token}`;
}

/**
 * Compute the `expires_at` timestamp for a new invite.
 *
 * - Clamps `expiresInDays` to `[1, MAX_INVITE_EXPIRY_DAYS]`.
 * - Falls back to `DEFAULT_INVITE_EXPIRY_DAYS` for missing input.
 * - `now` is injectable so tests don't need timer mocking.
 */
export function inviteExpiresAt(
  expiresInDays: number | undefined,
  now: Date = new Date(),
): Date {
  const days = clampExpiryDays(expiresInDays);
  const ms = days * 24 * 60 * 60 * 1000;
  return new Date(now.getTime() + ms);
}

/** Exposed for tests and for the API route that echoes the clamped value back. */
export function clampExpiryDays(expiresInDays: number | undefined): number {
  if (
    expiresInDays === undefined ||
    !Number.isFinite(expiresInDays) ||
    expiresInDays <= 0
  ) {
    return DEFAULT_INVITE_EXPIRY_DAYS;
  }
  return Math.min(Math.floor(expiresInDays), MAX_INVITE_EXPIRY_DAYS);
}

export function parseAllowedHosts(raw = process.env.ALLOWED_INVITE_HOSTS): readonly string[] | null {
  const trimmed = raw?.trim();
  if (!trimmed) return null;
  const list = trimmed
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return list.length > 0 ? list : null;
}

export function isHostAllowed(
  hostname: string,
  allowList: readonly string[] | null,
): boolean {
  if (!allowList) return true;
  return allowList.includes(hostname.toLowerCase());
}

/**
 * Resolve the base URL we publish invite links under.
 *
 * 1. `NEXT_PUBLIC_SITE_URL` — explicit config (unless it is a placeholder like `example.com`).
 * 2. `X-Forwarded-Host` (+ `X-Forwarded-Proto`) — set by proxies (Vercel, Cloudflare, etc.).
 * 3. `Host` header + request URL protocol.
 * 4. Fallback to `NEXT_PUBLIC_SITE_URL` (if set) or `https://wacrm.tech`.
 */
export function getBaseUrl(request: Request): string {
  const explicit = process.env.NEXT_PUBLIC_SITE_URL?.trim();
  // Don't treat dummy/example placeholder domains as an explicit configuration
  if (explicit && !explicit.includes("example.com")) {
    return explicit.replace(/\/+$/, "");
  }

  const allowList = parseAllowedHosts();
  const forwardedHost = request.headers
    .get("x-forwarded-host")
    ?.split(",")[0]
    ?.trim();
  const forwardedProto = request.headers
    .get("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim();
  if (forwardedHost && isHostAllowed(forwardedHost, allowList)) {
    return `${forwardedProto || "https"}://${forwardedHost}`;
  }

  const host = request.headers.get("host")?.trim();
  if (host && isHostAllowed(host, allowList)) {
    const reqProto = new URL(request.url).protocol.replace(":", "");
    return `${reqProto}://${host}`;
  }

  if (explicit) return explicit.replace(/\/+$/, "");

  if (allowList && (forwardedHost || host)) {
    console.warn(
      "[POST /api/account/invitations] rejected non-allow-listed host:",
      { forwardedHost, host, allowList },
    );
  } else {
    console.warn(
      "[POST /api/account/invitations] could not derive base URL from request; falling back to marketing domain",
    );
  }
  return "https://wacrm.tech";
}
