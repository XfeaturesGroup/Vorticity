export const corsHeaders = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, DELETE, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
};

export function jsonResp(data, headers = corsHeaders, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, ...headers } });
}

export function errorResp(msg, headers = corsHeaders, status = 400) {
    return new Response(JSON.stringify({ error: msg }), { status, headers: { ...corsHeaders, ...headers } });
}