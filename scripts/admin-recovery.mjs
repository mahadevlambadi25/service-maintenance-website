import { loadLocalEnvFiles } from '../src/config.js';
import { closeDb, getDb } from '../src/db/database.js';
import { generateTotpSecret, hashPassword, randomToken } from '../src/lib/crypto.js';
import { isValidEmail } from '../src/lib/validation.js';
import { recordAudit, revokeUserSessions } from '../src/services/auth.js';

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (!item.startsWith('--')) continue;
    const eq = item.indexOf('=');
    if (eq !== -1) {
      args[item.slice(2, eq)] = item.slice(eq + 1);
    } else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
      args[item.slice(2)] = argv[i + 1];
      i += 1;
    } else {
      args[item.slice(2)] = true;
    }
  }
  return args;
}

function generateStrongPassword() {
  return `Sm-${randomToken(12)}!9`;
}

async function main() {
  loadLocalEnvFiles();
  const args = parseArgs(process.argv.slice(2));
  const email = String(args.email || process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const newEmailRaw = String(args['new-email'] || process.env.ADMIN_NEW_EMAIL || '').trim().toLowerCase();

  if (!email || !args['confirm-reset']) {
    console.log(
      [
        'Operator Staff Password & MFA Recovery Utility',
        '',
        'Usage:',
        '  node scripts/admin-recovery.mjs --email admin@smiaz.local --confirm-reset [--new-email admin@company.com] [--rotate-mfa] [--password-env NEW_ADMIN_PASSWORD]',
        '',
        'Environment Variables (can be placed temporarily in .env.local):',
        '  ADMIN_EMAIL                  Existing target staff email (if --email is omitted)',
        '  ADMIN_NEW_EMAIL              Optional new email address to assign to the account',
        '  NEW_ADMIN_PASSWORD           New strong password (min 12 chars)',
        '',
        'Options:',
        '  --email <email>              Existing target staff account email (required unless ADMIN_EMAIL is set)',
        '  --new-email <email>          Optional replacement email address for this user',
        '  --confirm-reset              Required explicit confirmation flag before modifying any database row',
        '  --password-env <VAR>         Read the new password (min 12 chars) from process.env[VAR] instead of NEW_ADMIN_PASSWORD / auto-generating',
        '  --rotate-mfa                 Generate a fresh RFC 6238 Base32 TOTP secret (recommended on recovery or post-seed rotation)',
        '',
        'No database records were modified.',
      ].join('\n')
    );
    process.exit(email ? 1 : 0);
  }

  if (newEmailRaw && !isValidEmail(newEmailRaw)) {
    throw new Error(`Invalid replacement email address: ${newEmailRaw}`);
  }

  let newPassword = '';
  const passEnvName = args['password-env'] ? String(args['password-env']) : (process.env.NEW_ADMIN_PASSWORD ? 'NEW_ADMIN_PASSWORD' : '');
  if (passEnvName) {
    newPassword = String(process.env[passEnvName] || '');
    if (newPassword.length < 12) {
      throw new Error(`Environment variable ${passEnvName} must contain a password of at least 12 characters.`);
    }
  } else {
    newPassword = generateStrongPassword();
  }

  const db = await getDb();
  try {
    const user = await db.prepare('SELECT user_id, email, full_name, role, totp_secret, mfa_enabled, active FROM users WHERE email = ?').get(email);
    if (!user) {
      throw new Error(`No staff account found for email: ${email}`);
    }

    const nextEmail = newEmailRaw || user.email;
    if (nextEmail !== user.email) {
      const collision = await db.prepare('SELECT user_id FROM users WHERE email = ? AND user_id != ?').get(nextEmail, user.user_id);
      if (collision) {
        throw new Error(`Another account already uses email: ${nextEmail}`);
      }
    }

    const nowIso = new Date().toISOString();
    const nextPasswordHash = hashPassword(newPassword);
    const rotateMfa = Boolean(args['rotate-mfa']);
    const nextTotpSecret = rotateMfa ? generateTotpSecret() : user.totp_secret;

    await db
      .prepare(
        `UPDATE users
         SET email = ?, password_hash = ?, totp_secret = ?, mfa_enabled = 1, active = 1, updated_at = ?
         WHERE user_id = ?`
      )
      .run(nextEmail, nextPasswordHash, nextTotpSecret, nowIso, user.user_id);

    await revokeUserSessions(db, user.user_id);
    await recordAudit(
      db,
      { user_id: 'operator-cli', full_name: 'Operator Recovery CLI', role: 'Operator' },
      'auth',
      'operator_credential_recovery',
      'user',
      user.user_id,
      { email_changed: nextEmail !== user.email, rotated_mfa: rotateMfa, sessions_revoked: true }
    );

    const issuer = 'ServiceMaintenanceAdmin';
    const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(nextEmail)}?secret=${nextTotpSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    console.log(`Updated credentials for ${nextEmail} (${user.role}) and revoked all active sessions.`);
    if (!passEnvName) {
      console.log(`Generated strong password: ${newPassword}`);
    } else {
      console.log(`Password updated securely from environment variable ${passEnvName} (value not printed).`);
    }
    if (rotateMfa) {
      console.log(`New TOTP secret rotated (Base32): ${nextTotpSecret}`);
      console.log(`Authenticator URI: ${otpauthUri}`);
    } else {
      console.log('Existing TOTP secret preserved (pass --rotate-mfa to issue a new TOTP secret).');
    }
  } finally {
    await closeDb();
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
