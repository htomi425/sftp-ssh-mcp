export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname !== '/test') return new Response('Not found', { status: 404 });
    const resource = 'https://resource.example.invalid/mcp';
    const token = request.headers.get('Authorization')?.replace(/^Bearer /, '') || '';
    const result = await env.AUTH_SERVER.validateToken(resource, token);
    return Response.json(result);
  },
};
