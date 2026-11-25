/**
 * Microsoft 365 Email Delivery via Microsoft Graph API v1.0 (OAuth 2.0 Client Credentials Flow).
 * Official endpoint pattern:
 *   Token:    POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
 *   SendMail: POST https://graph.microsoft.com/v1.0/users/{sender}/sendMail
 *
 * Requires Application permission Mail.Send with admin consent in Microsoft Entra ID.
 * Never marks notifications as sent unless Microsoft Graph returns HTTP 202 (or 2xx).
 */

let cachedToken = null;
let cachedTokenExpiresAtMs = 0;
let customFetchImpl = null;

export function setMailerFetch(fetchFn) {
  customFetchImpl = fetchFn || null;
}

export function clearMailerTokenCache() {
  cachedToken = null;
  cachedTokenExpiresAtMs = 0;
}

function getGraphConfig() {
  return {
    tenantId: process.env.MS_GRAPH_TENANT_ID || '',
    clientId: process.env.MS_GRAPH_CLIENT_ID || '',
    clientSecret: process.env.MS_GRAPH_CLIENT_SECRET || '',
    sender: process.env.M365_SENDER || 'notifications@smiaz.com',
  };
}

async function getAccessToken(cfg, fetchFn) {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAtMs - 60_000) {
    return { ok: true, token: cachedToken };
  }

  const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(cfg.tenantId)}/oauth2/v2.0/token`;
  const form = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    scope: 'https://graph.microsoft.com/.default',
  });

  let res;
  try {
    res = await fetchFn(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
  } catch (err) {
    return { ok: false, transient: true, error: `Entra token network error: ${err.message}` };
  }

  if (res.status === 429 || res.status >= 500) {
    return { ok: false, transient: true, error: `Entra token HTTP ${res.status}` };
  }
  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    return { ok: false, transient: false, error: `Entra token rejected (${res.status}): ${errBody.slice(0, 140)}` };
  }

  const json = await res.json();
  if (!json?.access_token) {
    return { ok: false, transient: false, error: 'Entra token response missing access_token.' };
  }

  cachedToken = json.access_token;
  const expiresInSec = Number(json.expires_in || 3600);
  cachedTokenExpiresAtMs = now + expiresInSec * 1000;
  return { ok: true, token: cachedToken };
}

export async function sendEmailViaMicrosoftGraph({ to, subject, bodyText, replyTo = null }) {
  const cfg = getGraphConfig();
  if (!cfg.tenantId || !cfg.clientId || !cfg.clientSecret || !cfg.sender) {
    return {
      ok: false,
      transient: false,
      error: 'Microsoft Graph email not configured (set MS_GRAPH_TENANT_ID, MS_GRAPH_CLIENT_ID, MS_GRAPH_CLIENT_SECRET, M365_SENDER).',
    };
  }

  const fetchFn = customFetchImpl || globalThis.fetch;
  const auth = await getAccessToken(cfg, fetchFn);
  if (!auth.ok) return auth;

  const sendUrl = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(cfg.sender)}/sendMail`;
  const message = {
    subject: String(subject || '').slice(0, 250),
    body: {
      contentType: 'Text',
      content: String(bodyText || ''),
    },
    toRecipients: [
      {
        emailAddress: { address: String(to).trim() },
      },
    ],
  };

  if (replyTo && String(replyTo).includes('@')) {
    message.replyTo = [{ emailAddress: { address: String(replyTo).trim() } }];
  }

  let res;
  try {
    res = await fetchFn(sendUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${auth.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ message, saveToSentItems: true }),
    });
  } catch (err) {
    return { ok: false, transient: true, error: `Graph sendMail network error: ${err.message}` };
  }

  // If token unexpectedly expired early, clear cache and allow transient retry
  if (res.status === 401) {
    clearMailerTokenCache();
    return { ok: false, transient: true, error: 'Graph sendMail HTTP 401 (token refreshed for retry)' };
  }
  if (res.status === 429 || res.status >= 500) {
    return { ok: false, transient: true, error: `Graph sendMail HTTP ${res.status}` };
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    return { ok: false, transient: false, error: `Graph sendMail rejected (${res.status}): ${errText.slice(0, 140)}` };
  }

  const requestId = res.headers?.get?.('request-id') || res.headers?.get?.('x-ms-request-id') || `graph_${Date.now()}`;
  return { ok: true, providerMessageId: requestId };
}
