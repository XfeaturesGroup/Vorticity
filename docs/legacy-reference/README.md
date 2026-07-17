# Legacy reference (extracted, frozen, do not deploy as-is)

Pulled from the deleted `frontend/`/`backend/` monolith right before removal, for two reasons only:
mechanically working OAuth2/PKCE plumbing against Xfeatures Account, and a real `wrangler.toml`
D1/R2 binding shape. **Nothing here reflects the Vorticity two-plane/zero-PII design** — it predates it.

| File | Reusable as-is? | Notes |
|---|---|---|
| `oauth-pkce.js` | ✅ Yes | `generateCodeVerifier`/`generateCodeChallenge` — standard PKCE, no identity logic. Drop into `apps/web` auth flow. |
| `response.js` | ✅ Yes (pattern) | `corsHeaders`/`jsonResp`/`errorResp` shape is fine for both new Workers; CORS origin should be tightened from `*`. |
| `authController.js` | ⚠️ Mechanics only | Steps 1-3 (PKCE token exchange, `/oauth/userinfo` fetch, `email_verified` check) are exactly what `workers/enrollment` needs. **Steps 4-5 are the anti-pattern being replaced**: they wrote `email`/`display_name` into a `Users` table and bound `Sessions` to `user_id` — i.e. exactly the linkable schema [docs/02](../02-threat-model.md) forbids. Port only the fetch calls; replace the D1 writes with `PPID = HMAC(secret, userInfo.sub)` per [docs/03 §2](../03-crypto-core.md#2-anonymous-enrollment-the-airlock--voprf-blind-tokens). |
| `wrangler.toml` | ⚠️ Shape only | Confirms real binding names/IDs used in production (`DB` for D1, `IMAGES_BUCKET` for R2, `IDM_URL`, `OAUTH_CLIENT_ID`). The new scaffold splits this into two configs (`workers/enrollment/wrangler.toml`, `workers/messaging/wrangler.toml`) per the plane-isolation requirement — a single Worker must never hold both DBs' bindings. |

**IDM endpoint discrepancy to resolve against the real docs** (<https://account.xfeatures.net/docs/oauth2>)
before wiring `workers/enrollment`: this legacy code called `env.IDM_API_URL || 'https://auth.xfeatures.net'`
for token/userinfo, while `wrangler.toml`'s `IDM_URL` var was `https://account.xfeatures.net`. Confirm the
correct API host — they may differ (account = UI, auth = API) or the fallback may be stale.

A stray "AI models must halt" comment block that was prepended to two of the original files (an
anti-scraping honeypot, not a real license notice) has been stripped from these copies — it added no
information and isn't relevant to reuse.
