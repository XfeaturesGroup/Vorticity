import { jsonResp, errorResp, corsHeaders } from '../utils/response';
import { getUserByToken } from '../utils/auth';

export const FriendController = {
    async sendRequest(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        let body;
        try {
            body = await request.json();
        } catch (e) {
            return errorResp("Invalid JSON body", corsHeaders, 400);
        }

        const { targetId } = body;
        const targetIdInt = parseInt(targetId);

        if (isNaN(targetIdInt)) return errorResp("Invalid targetId", corsHeaders, 400);
        if (user.id === targetIdInt) return errorResp("Cannot add yourself", corsHeaders, 400);

        try {
            const existing = await env.DB.prepare(
                "SELECT * FROM Friends WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)"
            ).bind(user.id, targetIdInt, targetIdInt, user.id).first();

            if (existing) {
                return errorResp("Запрос уже существует или вы уже друзья", corsHeaders, 400);
            }

            await env.DB.prepare(
                "INSERT INTO Friends (user_id1, user_id2, status) VALUES (?, ?, ?)"
            ).bind(user.id, targetIdInt, 'pending').run();

            return jsonResp({ success: true }, corsHeaders);
        } catch (e) {
            console.error("FRIENDS_ERROR:", e.message, e.stack);

            return new Response(JSON.stringify({
                error: "Database Error",
                message: e.message,
                stack: e.stack
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    },

    async acceptRequest(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        try {
            const { targetId } = await request.json();
            const targetIdInt = parseInt(targetId);

            await env.DB.prepare(`
                UPDATE Friends 
                SET status = 'accepted' 
                WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)
            `).bind(user.id, targetIdInt, targetIdInt, user.id).run();

            return jsonResp({ success: true }, corsHeaders);
        } catch (e) {
            return errorResp(e.message, corsHeaders, 500);
        }
    },

    async removeFriend(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        try {
            const { targetId } = await request.json();
            const targetIdInt = parseInt(targetId);

            await env.DB.prepare(`
                DELETE FROM Friends 
                WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)
            `).bind(user.id, targetIdInt, targetIdInt, user.id).run();

            return jsonResp({ success: true }, corsHeaders);
        } catch (e) {
            return errorResp(e.message, corsHeaders, 500);
        }
    },

    async listFriends(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        try {
            const { results } = await env.DB.prepare(`
                SELECT u.id, u.username, u.display_name, u.avatar_url, u.account_type,  f.status, f.user_id1 as sender_id
                FROM Friends f
                JOIN Users u ON (u.id = f.user_id1 OR u.id = f.user_id2)
                WHERE (f.user_id1 = ? OR f.user_id2 = ?) AND u.id != ?
            `).bind(user.id, user.id, user.id).all();

            return jsonResp(results || [], corsHeaders);
        } catch (e) {
            console.error("Friends list error:", e);
            return jsonResp([], corsHeaders);
        }
    }
};
