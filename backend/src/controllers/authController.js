import { jsonResp, errorResp, corsHeaders } from '../utils/response';

export const AuthController = {
    async oauthCallback(request, env) {
        try {
            const { code, code_verifier, redirect_uri } = await request.json();

            if (!code || !code_verifier || !redirect_uri) {
                return errorResp("Отсутствуют необходимые параметры OAuth", corsHeaders, 400);
            }

            const idmUrl = env.IDM_URL || 'https://account.xfeatures.net';
            const clientId = env.OAUTH_CLIENT_ID || 'xf_9116480c21a94a849a1182717e35f335';

            // 1. Exchange code for access token
            const tokenParams = new URLSearchParams();
            tokenParams.set('grant_type', 'authorization_code');
            tokenParams.set('client_id', clientId);
            tokenParams.set('client_secret', (env.OAUTH_CLIENT_SECRET || '').trim());
            tokenParams.set('code', code);
            tokenParams.set('redirect_uri', redirect_uri);
            tokenParams.set('code_verifier', code_verifier);

            const tokenRes = await fetch(`${idmUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: tokenParams.toString()
            });

            if (!tokenRes.ok) {
                const errText = await tokenRes.text();
                console.error("Token exchange failed:", errText);
                return errorResp(`Ошибка IDM: ${errText}`, corsHeaders, 400);
            }

            const tokenData = await tokenRes.json();
            const accessToken = tokenData.access_token;

            // 2. Fetch User Info
            const userInfoRes = await fetch(`${idmUrl}/oauth/userinfo`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });

            if (!userInfoRes.ok) {
                return errorResp("Ошибка при получении профиля из IDM", corsHeaders, 400);
            }

            const userInfo = await userInfoRes.json();
            
            // 3. Verify email
            if (!userInfo.email_verified) {
                return errorResp("Для входа обязательно должна быть верифицирована почта.", corsHeaders, 403);
            }

            const email = userInfo.email;
            if (!email) {
                return errorResp("IDM не предоставил email адрес.", corsHeaders, 400);
            }

            // 4. Merge or Create User
            let user = await env.DB.prepare(
                "SELECT * FROM Users WHERE email = ?"
            ).bind(email).first();

            let userId;
            const fullName = [userInfo.given_name, userInfo.family_name].filter(Boolean).join(' ');
            const displayName = userInfo.name || fullName || userInfo.preferred_username || email.split('@')[0];
            const username = userInfo.preferred_username || email.split('@')[0];
            const avatarUrl = userInfo.picture || null;

            if (user) {
                // Merge/Update existing account
                userId = user.id;
                await env.DB.prepare(
                    "UPDATE Users SET display_name = COALESCE(?, display_name), avatar_url = COALESCE(?, avatar_url) WHERE id = ?"
                ).bind(displayName, avatarUrl, userId).run();
                
                // Fetch updated user
                user = await env.DB.prepare("SELECT * FROM Users WHERE id = ?").bind(userId).first();
            } else {
                // Check if username is taken
                let usernameCheck = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first();
                let finalUsername = username;
                let suffix = 1;
                while (usernameCheck) {
                    finalUsername = `${username}${suffix}`;
                    usernameCheck = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(finalUsername).first();
                    suffix++;
                }

                // Create new account
                const result = await env.DB.prepare(
                    "INSERT INTO Users (username, display_name, email, avatar_url) VALUES (?, ?, ?, ?) RETURNING *"
                ).bind(finalUsername, displayName, email, avatarUrl).first();
                
                user = result;
                userId = user.id;
            }

            // 5. Generate Session Token
            const sessionToken = crypto.randomUUID();
            // 30 days expiration
            const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

            await env.DB.prepare(
                "INSERT INTO Sessions (user_id, token, user_agent, expires_at) VALUES (?, ?, ?, ?)"
            ).bind(userId, sessionToken, request.headers.get('User-Agent') || 'Unknown', expiresAt).run();

            return jsonResp({
                token: sessionToken,
                user: {
                    id: userId,
                    username: user.username,
                    email: user.email,
                    display_name: user.display_name,
                    avatar_url: user.avatar_url
                }
            }, corsHeaders);

        } catch (err) {
            console.error("OAuth callback error:", err);
            return errorResp("Внутренняя ошибка сервера при обработке OAuth", corsHeaders, 500);
        }
    }
};
