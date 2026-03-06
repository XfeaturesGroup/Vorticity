export async function getUserByToken(request, env) {
    const token = request.headers.get('Authorization');
    if (!token) return null;

    const session = await env.DB.prepare(`
		SELECT u.* FROM Sessions s
		JOIN Users u ON s.user_id = u.id
		WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP
	`).bind(token).first();

    return session;
}