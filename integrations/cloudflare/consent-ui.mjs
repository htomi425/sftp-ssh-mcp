const escapeHtml = value => String(value).replace(/[&<>"']/g, character =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);

/**
 * Render only provider-derived consent information. Never use untrusted HTML.
 * The provider-issued handle is opaque; POST approval is handled separately.
 */
export function renderOAuthConsent({ details, consent }) {
  const handle = consent?.handle;
  if (typeof handle !== 'string' || !handle || handle.length > 2048) {
    throw new Error('OAuth provider did not issue a valid consent handle');
  }
  const clientName = details?.client?.client_name ?? details?.clientName ?? 'OAuth client';
  const scope = details?.scope ?? details?.scopes ?? ['mcp:invoke'];
  const scopes = Array.isArray(scope) ? scope : [];
  const scopeItems = scopes.map(value => '<li>' + escapeHtml(value) + '</li>').join('');
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>Authorize SSH MCP access</title></head><body><main>' +
    '<h1>Authorize SSH MCP access?</h1><p>Client: ' + escapeHtml(clientName) + '</p>' +
    '<p>Requested permissions:</p><ul>' + scopeItems + '</ul>' +
    '<p>Approval allows the client to invoke the MCP service subject to your server-side SSH target permissions.</p>' +
    '<form method="post" action="/authorize">' +
    '<input type="hidden" name="handle" value="' + escapeHtml(handle) + '">' +
    '<button type="submit" name="decision" value="approve">Approve</button>' +
    '<button type="submit" name="decision" value="deny">Deny</button>' +
    '</form></main></body></html>';
  const headers = new Headers(consent.headers);
  for (const [name, value] of Object.entries({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  })) headers.set(name, value);
  return new Response(html, { headers });
}
