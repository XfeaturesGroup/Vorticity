import { jsonResp, errorResp, corsHeaders } from '../utils/response';
import { getUserByToken } from '../utils/auth';

export const ChatController = {
    async listChats(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        try {
            const { results } = await env.DB.prepare(`
                SELECT c.id, c.created_at,
                       u.id as partner_id, u.username as partner_username, 
                       u.display_name as partner_display_name, u.avatar_url as partner_avatar,
                       (SELECT content FROM Messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
                       (SELECT created_at FROM Messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
                       (SELECT COUNT(*) FROM Messages WHERE chat_id = c.id AND sender_id != ? AND is_read = 0) as unread_count
                FROM Chats c
                JOIN Users u ON (u.id = CASE WHEN c.user_id1 = ? THEN c.user_id2 ELSE c.user_id1 END)
                WHERE (c.user_id1 = ? OR c.user_id2 = ?)
                ORDER BY COALESCE(last_message_at, c.created_at) DESC
            `).bind(user.id, user.id, user.id, user.id).all();

            return jsonResp(results || [], corsHeaders);
        } catch (e) {
            console.error("ListChats Error:", e);
            return errorResp(e.message, corsHeaders, 500);
        }
    },

    async getOrCreateChat(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        try {
            const { partnerId } = await request.json();
            const id1 = Math.min(user.id, partnerId);
            const id2 = Math.max(user.id, partnerId);

            let chat = await env.DB.prepare(
                "SELECT id FROM Chats WHERE user_id1 = ? AND user_id2 = ?"
            ).bind(id1, id2).first();

            if (!chat) {
                const result = await env.DB.prepare(
                    "INSERT INTO Chats (user_id1, user_id2) VALUES (?, ?)"
                ).bind(id1, id2).run();
                chat = { id: result.meta.last_row_id };
            }

            return jsonResp(chat, corsHeaders);
        } catch (e) {
            return errorResp(e.message, corsHeaders, 500);
        }
    },

    async getMessages(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        const chatId = Math.floor(Number(request.params.id));
        const cleanUserId = Math.floor(Number(user.id));

        try {
            const chat = await env.DB.prepare(
                "SELECT id FROM Chats WHERE id = ? AND (user_id1 = ? OR user_id2 = ?)"
            ).bind(chatId, cleanUserId, cleanUserId).first();

            if (!chat) return errorResp("Chat not found", corsHeaders, 404);

            const { results } = await env.DB.prepare(`
                SELECT * FROM Messages WHERE chat_id = ? ORDER BY created_at ASC
            `).bind(chatId).all();

            await env.DB.prepare(
                "UPDATE Messages SET is_read = 1 WHERE chat_id = ? AND sender_id != ?"
            ).bind(chatId, cleanUserId).run();

            const processedResults = (results || []).map(msg => {
                if (msg.attachments) {
                    try {
                        msg.attachments = JSON.parse(msg.attachments);
                    } catch (e) {
                        msg.attachments = [];
                    }
                } else {
                    msg.attachments = [];
                }
                return msg;
            });

            return jsonResp(processedResults, corsHeaders);
        } catch (e) {
            return errorResp(e.message, corsHeaders, 500);
        }
    },

    async sendMessage(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        try {
            const contentType = request.headers.get("content-type") || "";
            let chatId, content;
            let fileUrls = [];

            if (contentType.includes("multipart/form-data")) {
                const formData = await request.formData();
                chatId = formData.get("chatId");
                content = formData.get("content") || "";

                const files = formData.getAll("files");

                for (const file of files) {
                    if (file instanceof File) {
                        if (file.size > 25 * 1024 * 1024) {
                            return errorResp(`Файл ${file.name} превышает лимит.`, corsHeaders, 400);
                        }
                        const uniqueSuffix = crypto.randomUUID();
                        const safeFileName = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
                        const storageKey = `chats/${uniqueSuffix}_${safeFileName}`;

                        await env.IMAGES_BUCKET.put(storageKey, file.stream(), {
                            httpMetadata: { contentType: file.type }
                        });
                        fileUrls.push(`/images/${storageKey}`);
                    }
                }
            } else {
                const body = await request.json();
                chatId = body.chatId;
                content = body.content || "";
            }

            if (!chatId || (!content && fileUrls.length === 0)) {
                return errorResp("Пустое сообщение и нет файлов", corsHeaders, 400);
            }

            const cleanChatId = Math.floor(Number(chatId));
            const cleanUserId = Math.floor(Number(user.id));
            const attachmentsStr = fileUrls.length > 0 ? JSON.stringify(fileUrls) : null;

            const insertInfo = await env.DB.prepare(
                "INSERT INTO Messages (chat_id, sender_id, content, attachments) VALUES (?, ?, ?, ?)"
            ).bind(cleanChatId, cleanUserId, content, attachmentsStr).run();

            let messageId = insertInfo?.meta?.last_row_id;

            if (!messageId) {
                const idRow = await env.DB.prepare("SELECT last_insert_rowid() AS id").first();
                messageId = idRow?.id;
            }

            if (!messageId) {
                throw new Error("D1 не вернул last_row_id");
            }

            const result = await env.DB.prepare(
                "SELECT * FROM Messages WHERE id = ?"
            ).bind(messageId).first();

            if (!result) {
                throw new Error(`Сообщение с ID ${messageId} не найдено`);
            }

            if (result.attachments) {
                try { result.attachments = JSON.parse(result.attachments); }
                catch (e) { result.attachments = []; }
            } else {
                result.attachments = [];
            }

            return jsonResp(result, corsHeaders);
        } catch (e) {
            console.error("SendMessage Error:", e);
            return errorResp(e.message, corsHeaders, 500);
        }
    },

    async deleteMessage(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        const messageId = Math.floor(Number(request.params.id));

        const message = await env.DB.prepare("SELECT sender_id FROM Messages WHERE id = ?").bind(messageId).first();
        if (!message) return errorResp("Message not found", corsHeaders, 404);

        if (message.sender_id !== user.id) return errorResp("Forbidden", corsHeaders, 403);

        await env.DB.prepare("DELETE FROM Messages WHERE id = ?").bind(messageId).run();
        return jsonResp({ success: true }, corsHeaders);
    },

    async updateMessage(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Unauthorized", corsHeaders, 401);

        const messageId = Math.floor(Number(request.params.id));
        const { content } = await request.json();

        if (!content) return errorResp("Content is required", corsHeaders, 400);

        const message = await env.DB.prepare("SELECT sender_id FROM Messages WHERE id = ?").bind(messageId).first();
        if (!message) return errorResp("Message not found", corsHeaders, 404);

        if (message.sender_id !== user.id) return errorResp("Forbidden", corsHeaders, 403);

        await env.DB.prepare("UPDATE Messages SET content = ?, is_edited = 1 WHERE id = ?").bind(content, messageId).run();
        return jsonResp({ success: true }, corsHeaders);
    },

    async getCloudKey(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);

        const row = await env.DB.prepare("SELECT encrypted_private_key FROM UserKeys WHERE user_id = ?").bind(user.id).first();
        return jsonResp({ encryptedPrivateKey: row?.encrypted_private_key || null }, corsHeaders);
    },

    async initKeys(request, env) {
        const user = await getUserByToken(request, env);
        if (!user) return errorResp("Не авторизован", corsHeaders, 401);
        const { publicKey, encryptedPrivateKey } = await request.json();

        if (!publicKey || !encryptedPrivateKey) return errorResp("Требуется publicKey и encryptedPrivateKey", corsHeaders, 400);

        await env.DB.prepare(`
            INSERT INTO UserKeys (user_id, public_key, encrypted_private_key)
            VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                public_key = excluded.public_key,
                                            encrypted_private_key = excluded.encrypted_private_key,
                                            updated_at = CURRENT_TIMESTAMP
        `).bind(user.id, publicKey, encryptedPrivateKey).run();

        return jsonResp({ success: true }, corsHeaders);
    },

    async getPublicKey(request, env) {
        const userId = request.params.userId;
        const row = await env.DB.prepare("SELECT public_key FROM UserKeys WHERE user_id = ?").bind(userId).first();
        if (!row) return errorResp("Ключ не найден", corsHeaders, 404);
        return jsonResp({ publicKey: row.public_key }, corsHeaders);
    }
};