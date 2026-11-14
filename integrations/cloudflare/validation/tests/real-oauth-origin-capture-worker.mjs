export default {
  async fetch(request) {
    const authorization = request.headers.get('Authorization') || '';
    if (!/^Bearer [^.]+\.[^.]+\.[^.]+$/.test(authorization)) return new Response('missing gateway assertion', { status: 401 });
    if (request.headers.has('x-user') || request.headers.has('x-targets')) return new Response('forged identity forwarded', { status: 403 });
    return new Response(JSON.stringify({
      assertion: authorization.slice(7),
      body: await request.text(),
      method: request.method,
      path: new URL(request.url).pathname,
    }), { headers: { 'content-type': 'application/json' } });
  },
};
