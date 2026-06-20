import { timingSafeEqual } from 'node:crypto'

/**
 * Shared auth gate for the scheduled cron endpoints
 * (`/api/automations/cron`, `/api/flows/cron`).
 *
 * The secret may arrive two ways, so a single deployment works with
 * either trigger:
 *   - `x-cron-secret: <secret>` — external pingers (cron-job.org,
 *     GitHub Actions, a manual curl).
 *   - `Authorization: Bearer <secret>` — Vercel Cron, which can't set
 *     custom headers and instead injects this automatically when a
 *     `CRON_SECRET` env var is present. Set `CRON_SECRET` to the same
 *     value as `AUTOMATION_CRON_SECRET` so the Bearer token matches.
 *
 * Returns the HTTP status the caller should short-circuit with, or
 * `null` when the request is authorised and may proceed:
 *   503 — `AUTOMATION_CRON_SECRET` is unset (cron disabled).
 *   401 — missing / wrong secret.
 */
export function checkCronAuth(request: Request): 401 | 503 | null {
  const expected = process.env.AUTOMATION_CRON_SECRET
  if (!expected) return 503

  const bearer = request.headers
    .get('authorization')
    ?.replace(/^Bearer\s+/i, '')
  const supplied = request.headers.get('x-cron-secret') ?? bearer ?? ''

  // Constant-time compare so an attacker who can hit the endpoint can't
  // recover the secret byte-by-byte from response-time deltas. The
  // length pre-check is required by timingSafeEqual (it throws on
  // unequal lengths) and leaks only the length, which isn't sensitive.
  const suppliedBuf = Buffer.from(supplied)
  const expectedBuf = Buffer.from(expected)
  if (
    suppliedBuf.length !== expectedBuf.length ||
    !timingSafeEqual(suppliedBuf, expectedBuf)
  ) {
    return 401
  }

  return null
}
