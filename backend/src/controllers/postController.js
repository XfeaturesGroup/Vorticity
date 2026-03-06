import { jsonResp, errorResp, corsHeaders } from '../utils/response';
import { getUserByToken } from '../utils/auth';

export const PostController = {
    async list(request, env) {
        const url = new URL(request.url);
        const user = await getUserByToken(request, env);
        const currentUserId = user ? user.id : 0;

        const cursor = parseInt(url.searchParams.get('cursor')) || null;
        const offset = parseInt(url.searchParams.get('offset')) || 0;
        const limit = Math.min(parseInt(url.searchParams.get('limit')) || 20, 50);
        const tab = url.searchParams.get('tab') || 'recommended';

        let query = `
			SELECT 
				p.*, 
				u.username, 
				u.display_name,
				u.avatar_url,
                u.account_type,
				(SELECT COUNT(*) FROM Likes WHERE post_id = p.id) as likes_count,
				(SELECT COUNT(*) FROM Comments WHERE post_id = p.id) as comments_count,
				EXISTS(SELECT 1 FROM Likes WHERE post_id = p.id AND user_id = ?) as is_liked
			FROM Posts p
			JOIN Users u ON p.user_id = u.id
            WHERE 1=1
		`;

        let queryParams = [currentUserId];

        if (tab === 'recommended' && currentUserId > 0) {
            query += ` AND NOT EXISTS (SELECT 1 FROM PostViews WHERE post_id = p.id AND user_id = ?)`;
            queryParams.push(currentUserId);
        }

        if (tab === 'new') {
            if (cursor) {
                query += ` AND p.id < ?`;
                queryParams.push(cursor);
            }
            query += ` ORDER BY p.id DESC LIMIT ?`;
            queryParams.push(limit);
        } else {
            query += ` ORDER BY (likes_count * 2) + comments_count DESC, p.created_at DESC LIMIT ? OFFSET ?`;
            queryParams.push(limit, offset);
        }

        const stmt = await env.DB.prepare(query).bind(...queryParams);
        const response = await stmt.all();

        return jsonResp(response.results, corsHeaders);
    },

    async create(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);

        const formData = await request.formData();
        const content = formData.get('content');
        const files = formData.getAll('images');

        if ((!content || content.length > 4000) && files.length === 0) {
            return jsonResp({ error: "Текст поста должен быть до 4000 символов" }, corsHeaders, 400);
        }

        const uploadedUrls = [];
        for (const file of files) {
            if (file instanceof File && file.size > 0) {
                const uuid = crypto.randomUUID().replace(/-/g, '');
                const extension = file.name.split('.').pop();
                const fileKey = `${uuid}.${extension}`;

                await env.IMAGES_BUCKET.put(fileKey, file.stream(), {
                    httpMetadata: { contentType: file.type }
                });

                uploadedUrls.push(`https://vort.xfeatures.net/images/${fileKey}`);
            }
        }

        const imagesJson = uploadedUrls.length > 0 ? JSON.stringify(uploadedUrls) : null;

        let tagsJson = '[]';
        if (content) {
            const tagsMatch = content.match(/#([a-zA-Z0-9_А-Яа-яЁё]+)/g);
            if (tagsMatch) {
                const cleanedTags = [...new Set(tagsMatch.map(t => t.slice(1).toLowerCase()))];
                tagsJson = JSON.stringify(cleanedTags);
            }
        }

        await env.DB.prepare("INSERT INTO Posts (user_id, content, images, tags) VALUES (?, ?, ?, ?)")
            .bind(user.id, content, imagesJson, tagsJson)
            .run();

        return jsonResp({ success: true }, corsHeaders);
    },

    async delete(request, env) {
        const url = new URL(request.url);
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);

        const postId = url.pathname.split("/").pop();

        const post = await env.DB.prepare("SELECT user_id FROM Posts WHERE id = ?").bind(postId).first();
        if (!post) return errorResp("Пост не найден", corsHeaders, 404);
        if (post.user_id !== user.id) return errorResp("Нет прав на удаление", corsHeaders, 403);

        await env.DB.prepare("DELETE FROM Posts WHERE id = ? AND user_id = ?").bind(postId, user.id).run();
        return jsonResp({ success: true }, corsHeaders);
    },

    async update(request, env) {
        const url = new URL(request.url);
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);

        const postId = url.pathname.split("/").pop();
        const { content } = await request.json();

        if ((!content || content.length > 4000)) {
            return jsonResp({ error: "Текст поста должен быть до 4000 символов" }, corsHeaders, 400);
        }

        const post = await env.DB.prepare("SELECT user_id FROM Posts WHERE id = ?").bind(postId).first();
        if (!post) return errorResp("Пост не найден", corsHeaders, 404);
        if (post.user_id !== user.id) return errorResp("Нет прав на редактирование", corsHeaders, 403);

        await env.DB.prepare("UPDATE Posts SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?")
            .bind(content, postId, user.id)
            .run();

        return jsonResp({ success: true }, corsHeaders);
    },

    async like(request, env) {
        const url = new URL(request.url);
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);
        const postId = url.pathname.split("/")[2];

        const existing = await env.DB.prepare("SELECT id FROM Likes WHERE user_id = ? AND post_id = ?")
            .bind(user.id, postId).first();

        if (existing) {
            await env.DB.prepare("DELETE FROM Likes WHERE id = ?").bind(existing.id).run();
            return jsonResp({ liked: false }, corsHeaders);
        } else {
            await env.DB.prepare("INSERT INTO Likes (user_id, post_id) VALUES (?, ?)").bind(user.id, postId).run();
            return jsonResp({ liked: true }, corsHeaders);
        }
    },

    async getComments(request, env) {
        const { postId } = request.params;
        const { results } = await env.DB.prepare(`
            SELECT c.*, u.display_name, u.username, u.avatar_url, u.account_type
            FROM Comments c
            JOIN Users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        `).bind(postId).all();

        return jsonResp(results || [], corsHeaders);
    },

    async addComment(request, env) {
        const url = new URL(request.url);
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);

        const postId = url.pathname.split("/")[2];
        const { content } = await request.json();

        if (!content || content.length > 200) return errorResp("Комментарий слишком длинный или пустой", corsHeaders, 400);

        await env.DB.prepare("INSERT INTO Comments (user_id, post_id, content) VALUES (?, ?, ?)")
            .bind(user.id, postId, content).run();

        return jsonResp({ success: true }, corsHeaders);
    },

    async recordViews(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return jsonResp({ success: false }, corsHeaders, 401);

        const { postIds } = await request.json();
        if (!postIds || !Array.isArray(postIds) || postIds.length === 0) {
            return jsonResp({ success: true }, corsHeaders);
        }

        const stmt = env.DB.prepare("INSERT OR IGNORE INTO PostViews (user_id, post_id) VALUES (?, ?)");
        const batch = postIds.map(id => stmt.bind(user.id, id));

        await env.DB.batch(batch);

        return jsonResp({ success: true }, corsHeaders);
    }
};