import { corsHeaders, errorResp } from '../utils/response';

export const ImageController = {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const key = url.pathname.replace("/images/", "");
        const cache = caches.default;

        let response = await cache.match(request);
        if (response) return response;

        const object = await env.IMAGES_BUCKET.get(key);
        if (!object) {
            return errorResp("Not Found", corsHeaders, 404);
        }

        const headers = new Headers(corsHeaders);
        object.writeHttpMetadata(headers);
        headers.set("etag", object.httpEtag);
        headers.set("Cache-Control", "public, max-age=31536000, immutable");

        response = new Response(object.body, { headers });

        ctx.waitUntil(cache.put(request, response.clone()));

        return response;
    }
};