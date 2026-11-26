import { ENV, loadLocalEnvFiles } from '../src/config.js';
import { closeDb, getDb } from '../src/db/database.js';
import { issueMfaSetupToken } from '../src/services/auth.js';

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

async function main() {
  loadLocalEnvFiles();
  const args = parseArgs(process.argv.slice(2));
  const email = String(args.email || process.env.ADMIN_EMAIL || '').trim().toLowerCase();

  if (!email || !args.confirm) {
    console.log(
      [
        'Authorized MFA Enrollment & Recovery Link Issuer',
        '',
        'Usage:',
        '  node scripts/admin-mfa-setup.mjs --email admin@smiaz.local --confirm [--purpose enroll|recovery] [--base-url http://127.0.0.1:3000]',
        '',
        'Options:',
        '  --email <email>         Target active staff email (or set ADMIN_EMAIL)',
        '  --purpose <mode>        "enroll" (first-time setup when mfa_enrolled=0) or "recovery" (re-enroll enrolled account)',
        '  --base-url <url>        Base URL for the setup link (default: ENV.BASE_URL)',
        '  --confirm               Required explicit flag before writing a single-use token hash',
        '',
        'No database records were modified. No secrets or passwords are printed.',
      ].join('\n')
    );
    process.exit(email ? 1 : 0);
  }

  const db = await getDb();
  try {
    const user = await db
      .prepare('SELECT user_id, email, role, mfa_enrolled, active FROM users WHERE email = ?')
      .get(email);
    if (!user || !user.active) {
      throw new Error(`No active staff account found for email: ${email}`);
    }

    const requestedPurpose = args.purpose
      ? String(args.purpose) === 'recovery'
        ? 'recovery'
        : 'first_time_enroll'
      : user.mfa_enrolled
        ? 'recovery'
        : 'first_time_enroll';

    const issued = await issueMfaSetupToken(db, {
      userId: user.user_id,
      purpose: requestedPurpose,
      issuedBy: 'operator-cli',
      ttlMinutes: 15,
    });
    if (!issued.ok) {
      throw new Error(issued.error);
    }

    const baseUrl = String(args['base-url'] || ENV.BASE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
    console.log(`Issued single-use 15-minute MFA ${issued.purpose} token (tokenId=${issued.tokenId}) for ${user.email}.`);
    console.log(`Expires at: ${issued.expiresAt}`);
    console.log(`Authorized setup URL: ${baseUrl}/admin/mfa-setup?token=${issued.rawToken}`);
  } finally {
    await closeDb();
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
