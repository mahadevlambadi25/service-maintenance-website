import { loadLocalEnvFiles } from '../src/config.js';
import { closeDb, getDb } from '../src/db/database.js';
import { generateTotpSecret, hashPassword, randomToken } from '../src/lib/crypto.js';
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
  const email = String(args.email || '').trim().toLowerCase();

  if (!email || !args['confirm-reset']) {
    console.log(
      [
        'Operator Staff Password & MFA Recovery Utility',
        '',
        'Usage:',
        '  node scripts/admin-recovery.mjs --email admin@smiaz.local --confirm-reset [--rotate-mfa] [--password-env NEW_ADMIN_PASSWORD]',
        '',
        'Options:',
        '  --email <email>              Target staff account email (required)',
        '  --confirm-reset              Required explicit confirmation flag before modifying any database row',
        '  --password-env <VAR>         Read the new password (min 12 chars) from process.env[VAR] instead of auto-generating one',
        '  --rotate-mfa                 Generate a fresh RFC 6238 Base32 TOTP secret (recommended on recovery or post-seed rotation)',
        '',
        'No database records were modified.',
      ].join('\n')
    );
    process.exit(email ? 1 : 0);
  }

  let newPassword = '';
  if (args['password-env']) {
    newPassword = String(process.env[String(args['password-env'])] || '');
    if (newPassword.length < 12) {
      throw new Error(`Environment variable ${args['password-env']} must contain a password of at least 12 characters.`);
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

    const nowIso = new Date().toISOString();
    const nextPasswordHash = hashPassword(newPassword);
    const rotateMfa = Boolean(args['rotate-mfa']);
    const nextTotpSecret = rotateMfa ? generateTotpSecret() : user.totp_secret;

    await db
      .prepare(
        `UPDATE users
         SET password_hash = ?, totp_secret = ?, mfa_enabled = 1, active = 1, updated_at = ?
         WHERE user_id = ?`
      )
      .run(nextPasswordHash, nextTotpSecret, nowIso, user.user_id);

    await revokeUserSessions(db, user.user_id);
    await recordAudit(
      db,
      { user_id: 'operator-cli', full_name: 'Operator Recovery CLI', role: 'Operator' },
      'auth',
      'operator_credential_recovery',
      'user',
      user.user_id,
      { rotated_mfa: rotateMfa, sessions_revoked: true }
    );

    const issuer = 'ServiceMaintenanceAdmin';
    const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${nextTotpSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    console.log(`Updated credentials for ${user.email} (${user.role}) and revoked all active sessions.`);
    console.log(`New password: ${newPassword}`);
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
