import crypto from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateUuid() {
  return crypto.randomUUID();
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, keyHex] = storedHash.split(':');
  const keyBuf = Buffer.from(keyHex, 'hex');
  const derivedBuf = crypto.scryptSync(password, salt, 64);
  if (keyBuf.length !== derivedBuf.length) return false;
  return crypto.timingSafeEqual(keyBuf, derivedBuf);
}

export function signHmac(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

export function verifyHmac(data, signature, secret) {
  const expected = signHmac(data, secret);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(signature || ''));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// RFC 6238 TOTP Implementation
export function generateTotpSecret(bytes = 20) {
  const buf = crypto.randomBytes(bytes);
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function decodeBase32(base32) {
  const clean = String(base32).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpCode(secret, timeMs = Date.now(), stepSeconds = 30) {
  const key = decodeBase32(secret);
  const counter = Math.floor(timeMs / 1000 / stepSeconds);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

export function verifyTotpCode(secret, token, timeMs = Date.now(), windowSteps = 2) {
  const clean = String(token || '').replace(/[\s-]+/g, '').trim();
  if (!/^\d{6}$/.test(clean)) return false;
  for (let offset = -windowSteps; offset <= windowSteps; offset++) {
    const expected = generateTotpCode(secret, timeMs + offset * 30_000);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) {
      return true;
    }
  }
  return false;
}

export function buildTotpOtpAuthUri({ issuer = 'ServiceMaintenance', email, secret }) {
  const label = `${issuer}:${email}`;
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

const DEFAULT_DEV_ENC_MATERIAL = 'dev-session-secret-change-in-production-32chars';

function deriveAesKey(keyMaterial) {
  const raw = String(keyMaterial || process.env.MFA_ENCRYPTION_KEY || process.env.SESSION_SECRET || '');
  const material = raw || (process.env.NODE_ENV === 'production' ? '' : DEFAULT_DEV_ENC_MATERIAL);
  if (!material) {
    throw new Error('MFA encryption key material is required in production.');
  }
  return crypto.createHash('sha256').update(`sm-mfa-at-rest-v1:${material}`).digest();
}

export function encryptSecret(plaintext, keyMaterial = '') {
  const value = String(plaintext || '');
  if (!value) return '';
  if (value.startsWith('enc:v1:')) return value;
  const key = deriveAesKey(keyMaterial);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptSecret(storedValue, keyMaterial = '') {
  const raw = String(storedValue || '').trim();
  if (!raw) return '';
  if (!raw.startsWith('enc:v1:')) return raw;
  const parts = raw.split(':');
  if (parts.length !== 5) return '';
  const [, , ivHex, tagHex, cipherHex] = parts;
  const key = deriveAesKey(keyMaterial);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(cipherHex, 'hex')), decipher.final()]);
  return decrypted.toString('utf8');
}

const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(10);
    let chars = '';
    for (let j = 0; j < 10; j++) {
      chars += RECOVERY_ALPHABET[bytes[j] % RECOVERY_ALPHABET.length];
    }
    codes.push(`${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 10)}`);
  }
  return codes;
}

export function normalizeRecoveryCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export function hashRecoveryCodeList(codes) {
  return codes.map((plain) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const normalized = normalizeRecoveryCode(plain);
    const hash = crypto.createHash('sha256').update(`${salt}:${normalized}`).digest('hex');
    return { id: generateUuid(), salt, hash, used_at: null };
  });
}

export function verifyRecoveryCodeInList(candidateCode, storedJson) {
  const normalized = normalizeRecoveryCode(candidateCode);
  if (normalized.length < 8) return { matched: false, codeId: null, entries: [] };
  let entries = [];
  try {
    entries = JSON.parse(storedJson || '[]');
  } catch {
    entries = [];
  }
  if (!Array.isArray(entries)) entries = [];
  for (const entry of entries) {
    if (!entry || entry.used_at || !entry.salt || !entry.hash) continue;
    const candidateHash = crypto.createHash('sha256').update(`${entry.salt}:${normalized}`).digest('hex');
    const a = Buffer.from(candidateHash, 'hex');
    const b = Buffer.from(String(entry.hash), 'hex');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return { matched: true, codeId: entry.id, entries };
    }
  }
  return { matched: false, codeId: null, entries };
}
