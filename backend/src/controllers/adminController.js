import { jsonResp, errorResp, corsHeaders } from '../utils/response';
import { getUserByToken } from '../utils/auth';
import { hashPasswordV2 } from '../utils/crypto';
import { isValidEmail, isValidUsername } from '../utils/validators';

export const AdminController = {
    async checkAdmin(request, env) {
        const user = await getUserByToken(request, env);
        if (!user || user.is_admin !== 1) {
            return null;
        }
        return user;
    },

    async getStats(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const users = await env.DB.prepare("SELECT COUNT(*) as c FROM Users").first();
        const posts = await env.DB.prepare("SELECT COUNT(*) as c FROM Posts").first();
        const comments = await env.DB.prepare("SELECT COUNT(*) as c FROM Comments").first();
        const likes = await env.DB.prepare("SELECT COUNT(*) as c FROM Likes").first();

        return jsonResp({
            users: users.c,
            posts: posts.c,
            comments: comments.c,
            likes: likes.c
        }, corsHeaders);
    },

    async getUsers(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page')) || 1;
        const limit = 20;
        const offset = (page - 1) * limit;
        const search = url.searchParams.get('q') || '';

        let query = "SELECT id, username, display_name, email, is_admin, account_type, avatar_url, created_at FROM Users";
        let params = [];

        if (search) {
            query += " WHERE username LIKE ? OR email LIKE ?";
            params.push(`%${search}%`, `%${search}%`);
        }

        query += " ORDER BY id DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);

        const { results } = await env.DB.prepare(query).bind(...params).all();
        return jsonResp(results, corsHeaders);
    },

    async updateUser(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const url = new URL(request.url);
        const targetId = parseInt(url.pathname.split('/')[3]);
        if (isNaN(targetId)) return errorResp("Invalid ID", corsHeaders, 400);

        const { username, display_name, email, password, bio, is_admin, account_type } = await request.json();

        if (username && !isValidUsername(username)) return errorResp("Некорректный логин", corsHeaders, 400);
        if (email && !isValidEmail(email)) return errorResp("Некорректная почта", corsHeaders, 400);

        let updates = [];
        let params = [];

        if (username) { updates.push("username = ?"); params.push(username); }
        if (display_name) { updates.push("display_name = ?"); params.push(display_name); }
        if (email) { updates.push("email = ?"); params.push(email); }
        if (bio) { updates.push("bio = ?"); params.push(bio); }
        if (typeof is_admin !== 'undefined') { updates.push("is_admin = ?"); params.push(is_admin); }
        if (typeof account_type !== 'undefined') { updates.push("account_type = ?"); params.push(account_type); }

        if (password) {
            const hash = await hashPasswordV2(password);
            updates.push("password_hash = ?");
            params.push(hash);
        }

        if (updates.length === 0) return errorResp("Нет данных для обновления", corsHeaders, 400);

        params.push(targetId);
        const query = `UPDATE Users SET ${updates.join(", ")} WHERE id = ?`;

        await env.DB.prepare(query).bind(...params).run();

        return jsonResp({ success: true }, corsHeaders);
    },

    async deleteUser(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const url = new URL(request.url);
        const targetId = parseInt(url.pathname.split('/')[3]);
        if (isNaN(targetId)) return errorResp("Invalid ID", corsHeaders, 400);

        try {
            await env.DB.batch([
                env.DB.prepare("DELETE FROM Likes WHERE user_id = ?").bind(targetId),
                env.DB.prepare("DELETE FROM Comments WHERE user_id = ?").bind(targetId),
                env.DB.prepare("DELETE FROM Sessions WHERE user_id = ?").bind(targetId),

                env.DB.prepare("DELETE FROM Likes WHERE post_id IN (SELECT id FROM Posts WHERE user_id = ?)").bind(targetId),
                env.DB.prepare("DELETE FROM Comments WHERE post_id IN (SELECT id FROM Posts WHERE user_id = ?)").bind(targetId),

                env.DB.prepare("DELETE FROM Posts WHERE user_id = ?").bind(targetId),

                env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetId)
            ]);

            return jsonResp({ success: true }, corsHeaders);
        } catch (err) {
            console.error("Delete User Error:", err);
            return errorResp("Ошибка при удалении пользователя", corsHeaders, 500);
        }
    },

    async deleteContent(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const url = new URL(request.url);
        const isPost = url.pathname.includes('/posts/');
        const type = isPost ? 'Posts' : 'Comments';
        const id = parseInt(url.pathname.split('/').pop());

        if (isNaN(id)) return errorResp("Invalid ID", corsHeaders, 400);

        const tableName = isPost ? "Posts" : "Comments";
        await env.DB.prepare(`DELETE FROM ${tableName} WHERE id = ?`).bind(id).run();

        return jsonResp({ success: true, message: `${type} deleted` }, corsHeaders);
    },

    async getMedia(request, env) {
        try {
            if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

            const url = new URL(request.url);
            const cursor = url.searchParams.get('cursor');
            const limit = 20;

            const listed = await env.IMAGES_BUCKET.list({ limit, cursor: cursor || undefined });

            if (!listed || !listed.objects) {
                return jsonResp({ objects: [], cursor: null, truncated: false }, corsHeaders);
            }

            const objects = await Promise.all(listed.objects.map(async (obj) => {
                let isUsed = false;
                try {
                    const [checkPost, checkAvatar, checkBanner] = await Promise.all([
                        env.DB.prepare("SELECT 1 FROM Posts WHERE images LIKE ? LIMIT 1").bind(`%${obj.key}%`).first(),
                        env.DB.prepare("SELECT 1 FROM Users WHERE avatar_url LIKE ? LIMIT 1").bind(`%${obj.key}%`).first(),
                        env.DB.prepare("SELECT 1 FROM Users WHERE banner_url LIKE ? LIMIT 1").bind(`%${obj.key}%`).first()
                    ]);

                    isUsed = !!(checkPost || checkAvatar || checkBanner);
                } catch (dbErr) {
                    console.error("DB Check Error:", dbErr);
                }

                return {
                    key: obj.key,
                    size: obj.size,
                    uploaded: obj.uploaded,
                    isUsed: isUsed,
                    url: `${url.origin}/images/${obj.key}`
                };
            }));

            return jsonResp({
                objects: objects,
                cursor: listed.cursor,
                truncated: listed.truncated
            }, corsHeaders);
        } catch (err) {
            console.error("Admin Media Error:", err);
            return errorResp("Internal Server Error", corsHeaders, 500);
        }
    },

    async deleteMedia(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const url = new URL(request.url);
        const key = url.pathname.replace('/admin/media/', '');

        if (!/^[a-zA-Z0-9._\-/]+$/.test(key)) {
            return errorResp("Invalid file key", corsHeaders, 400);
        }

        await env.IMAGES_BUCKET.delete(key);
        return jsonResp({ success: true }, corsHeaders);
    },

    async replaceMedia(request, env) {
        if (!(await AdminController.checkAdmin(request, env))) return errorResp("Access Denied", corsHeaders, 403);

        const url = new URL(request.url);
        const key = url.pathname.replace('/admin/media/', '');

        if (!/^[a-zA-Z0-9._\-/]+$/.test(key)) {
            return errorResp("Invalid file key", corsHeaders, 400);
        }

        const formData = await request.formData();
        const file = formData.get('file');

        if (!file) return errorResp("File required", corsHeaders, 400);

        await env.IMAGES_BUCKET.put(key, file.stream(), {
            httpMetadata: { contentType: file.type }
        });

        return jsonResp({ success: true }, corsHeaders);
    }
};
