// Token-exchange + userinfo mechanics, adapted from docs/legacy-reference/authController.js
// (steps 1-3 only — that file's steps 4-5, writing email into D1, are exactly the anti-pattern
// this rebuild removes; see docs/02-threat-model.md).
import type { Env } from "./env";

export interface XfeaturesUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
}

export async function exchangeCodeForUserInfo(
  env: Env,
  code: string,
  codeVerifier: string,
  redirectUri: string,
): Promise<XfeaturesUserInfo> {
  const tokenRes = await fetch(`${env.IDM_API_URL}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: env.OAUTH_CLIENT_ID,
      client_secret: env.OAUTH_CLIENT_SECRET.trim(),
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenRes.ok) {
    throw new Error(`IDM token exchange failed: ${await tokenRes.text()}`);
  }

  const { access_token } = (await tokenRes.json()) as { access_token: string };

  const userInfoRes = await fetch(`${env.IDM_API_URL}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });

  if (!userInfoRes.ok) {
    throw new Error("IDM userinfo fetch failed");
  }

  return (await userInfoRes.json()) as XfeaturesUserInfo;
}
