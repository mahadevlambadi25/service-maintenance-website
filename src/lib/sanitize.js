/**
 * HTML escaping, rich-text allowlist sanitization, URL protocol checks,
 * and MITRE CWE-1236 spreadsheet formula-injection neutralization.
 */

export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function isSafeUrl(url) {
  if (!url) return false;
  const trimmed = String(url).trim();
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) return true;
  if (trimmed.startsWith('#')) return true;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'mailto:' || parsed.protocol === 'tel:';
  } catch {
    return false;
  }
}

const ALLOWED_TAGS = new Set(['p', 'br', 'strong', 'b', 'em', 'i', 'ul', 'ol', 'li', 'h2', 'h3', 'h4', 'a', 'blockquote']);

/**
 * Server-side defense-in-depth HTML allowlist sanitizer.
 * Strips script/style/iframe/object/event handlers/unsafe protocols while preserving clean editorial HTML.
 */
export function sanitizeRichHtml(input) {
  if (!input) return '';
  let str = String(input);
  // Remove dangerous block elements along with their content
  str = str.replace(/<\s*(script|style|iframe|object|embed|svg|math|form|input|textarea|select|button)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, '');
  str = str.replace(/<\s*(script|style|iframe|object|embed|svg|math|form|input|textarea|select|button)\b[^>]*\/?>/gi, '');
  // Remove HTML comments
  str = str.replace(/<!--[\s\S]*?-->/g, '');

  // Filter tags and attributes
  str = str.replace(/<\/?([a-zA-Z0-9-]+)([^>]*)>/g, (full, tagName, attrs) => {
    const tag = tagName.toLowerCase();
    if (!ALLOWED_TAGS.has(tag)) return '';
    if (full.startsWith('</')) return `</${tag}>`;
    if (tag === 'br') return '<br>';
    if (tag === 'a') {
      const hrefMatch = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const rawHref = hrefMatch ? (hrefMatch[1] ?? hrefMatch[2] ?? hrefMatch[3] ?? '') : '';
      if (!isSafeUrl(rawHref)) return '<a>';
      return `<a href="${escapeHtml(rawHref)}">`;
    }
    return `<${tag}>`;
  });
  return str.trim();
}

/**
 * MITRE CWE-1236: Neutralizes spreadsheet formula injection on CSV/TSV cells.
 * Treats applicant/user-controlled values as text by prefixing leading =, +, -, @, tab, CR
 * (even after leading whitespace) with a single quote and quoting properly.
 */
export function csvSafeCell(value) {
  let str = value === null || value === undefined ? '' : String(value);
  // Normalize null bytes
  str = str.replace(/\0/g, '');
  // If starts with formula trigger (or whitespace followed by trigger), prefix with apostrophe
  if (/^[\s]*[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  const escaped = str.replace(/"/g, '""');
  return `"${escaped}"`;
}

export function buildSafeCsv(headers, rows) {
  const lines = [headers.map(csvSafeCell).join(',')];
  for (const row of rows) {
    lines.push(row.map(csvSafeCell).join(','));
  }
  return '\uFEFF' + lines.join('\r\n');
}

/**
 * Redacts PII (emails, phones, long free text) from routine operational logs.
 */
export function redactForLog(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  const sensitiveKeys = new Set(['email', 'phone', 'telephone', 'name', 'applicant_name', 'description', 'message', 'relevant_experience', 'resume', 'password', 'totp', 'token', 'notes']);
  for (const [k, v] of Object.entries(obj)) {
    if (sensitiveKeys.has(k.toLowerCase())) {
      out[k] = '[REDACTED]';
    } else if (typeof v === 'string' && v.length > 160) {
      out[k] = `${v.slice(0, 40)}...[TRUNCATED]`;
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = redactForLog(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}
