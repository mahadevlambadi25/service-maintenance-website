import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ENV, ROOT_DIR } from '../config.js';
import { escapeHtml, formatPublicAddress } from '../lib/sanitize.js';

function computeAssetVersion() {
  try {
    const hash = crypto.createHash('sha1');
    for (const rel of ['public/css/tokens.css', 'public/css/main.css', 'public/js/app.js']) {
      hash.update(fs.readFileSync(path.join(ROOT_DIR, rel)));
    }
    return hash.digest('hex').slice(0, 10);
  } catch {
    return '1';
  }
}

const ASSET_VERSION = computeAssetVersion();

export function buildJsonLdOrganization(settings) {
  return {
    '@context': 'https://schema.org',
    '@type': 'LocalBusiness',
    name: settings.trading_name,
    legalName: settings.legal_entity,
    url: ENV.BASE_URL,
    telephone: settings.phone_e164,
    areaServed: {
      '@type': 'AdministrativeArea',
      name: 'Greater Phoenix, Arizona',
    },
    address: {
      '@type': 'PostalAddress',
      streetAddress: '2105 S Hardy Dr., Suite 17',
      addressLocality: 'Tempe',
      addressRegion: 'AZ',
      addressCountry: 'US',
    },
  };
}

export function buildJsonLdBreadcrumbs(items) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, idx) => ({
      '@type': 'ListItem',
      position: idx + 1,
      name: item.label,
      item: item.href.startsWith('http') ? item.href : `${ENV.BASE_URL}${item.href}`,
    })),
  };
}

export function renderPublicLayout({
  title,
  metaDescription,
  canonicalPath,
  noindex = false,
  settings,
  noticeStrip = null,
  hasPublishedInsights = false,
  previewInfo = null,
  extraJsonLd = [],
  nonce = '',
  consentState = 'undecided',
  hideStickyCta = false,
  currentPath = '/',
  bodyHtml,
}) {
  const canonicalUrl = `${ENV.BASE_URL}${canonicalPath}`;
  const jsonLdBlocks = [buildJsonLdOrganization(settings), ...extraJsonLd];
  const currentYear = new Date().getFullYear();
  const robotsContent = noindex || ENV.IS_STAGING ? 'noindex, nofollow' : 'index, follow';

  const navItems = [
    { href: '/services/', label: 'Services' },
    { href: '/properties/', label: 'Properties' },
    { href: '/projects/', label: 'Projects' },
    { href: '/about/', label: 'About' },
    { href: '/credentials/', label: 'Credentials' },
    {
      href: '/careers/',
      label: 'Careers',
      children: [
        { href: '/careers/', label: 'Careers Overview' },
        { href: '/careers/#openings', label: 'Current Job Openings' },
        { href: '/careers/#apply', label: 'Application Process' },
      ],
    },
  ];
  if (hasPublishedInsights) {
    navItems.push({ href: '/insights/', label: 'Insights' });
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <meta name="description" content="${escapeHtml(metaDescription)}">
  <meta name="robots" content="${escapeHtml(robotsContent)}">
  <link rel="canonical" href="${escapeHtml(canonicalUrl)}">
  <meta property="og:title" content="${escapeHtml(title)}">
  <meta property="og:description" content="${escapeHtml(metaDescription)}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${escapeHtml(canonicalUrl)}">
  <link rel="icon" type="image/svg+xml" href="/assets/brand-mark.svg">
  <link rel="stylesheet" href="/css/tokens.css?v=${ASSET_VERSION}">
  <link rel="stylesheet" href="/css/main.css?v=${ASSET_VERSION}">
  ${jsonLdBlocks
    .map(
      (obj) =>
        `<script type="application/ld+json" nonce="${escapeHtml(nonce)}">${JSON.stringify(obj).replace(/</g, '\\u003c')}</script>`
    )
    .join('\n  ')}
</head>
<body data-consent="${escapeHtml(consentState)}" data-is-preview="${previewInfo ? '1' : '0'}">
  <a href="#main-content" class="skip-link">Skip to main content</a>

  ${
    previewInfo
      ? `<div class="preview-banner" role="status" style="display:flex;flex-wrap:wrap;gap:0.75rem;justify-content:center;align-items:center;">
          <span><strong>STAFF PREVIEW MODE (${previewInfo.viewport === 'mobile' ? 'Mobile 390px' : 'Desktop'})</strong> — Viewing ${escapeHtml(previewInfo.label)}${previewInfo.asOf ? ` | Simulated Phoenix time: ${escapeHtml(previewInfo.asOf)}` : ''} | Production analytics disabled.</span>
          ${
            previewInfo.desktopUrl && previewInfo.mobileUrl
              ? `<span style="display:inline-flex;gap:0.4rem;">
                  <a href="${escapeHtml(previewInfo.desktopUrl)}" class="badge"${previewInfo.viewport !== 'mobile' ? ' style="background:var(--color-oxide);color:#fff;border-color:var(--color-oxide);"' : ''}>Desktop Preview</a>
                  <a href="${escapeHtml(previewInfo.mobileUrl)}" class="badge"${previewInfo.viewport === 'mobile' ? ' style="background:var(--color-oxide);color:#fff;border-color:var(--color-oxide);"' : ''}>Mobile Preview (390px)</a>
                </span>`
              : ''
          }
          <a href="/admin/">Return to Dashboard</a>
        </div>`
      : ''
  }
  ${
    previewInfo?.viewport === 'mobile'
      ? `<div class="preview-viewport-frame" style="max-width:390px;margin:1rem auto;border:3px solid var(--color-carbon);border-radius:6px;overflow-x:hidden;box-shadow:0 12px 30px rgba(36,37,31,0.18);background:var(--color-limestone);">`
      : ''
  }

  ${
    noticeStrip
      ? `<div class="notice-strip" data-campaign-id="${escapeHtml(noticeStrip.campaign_id)}" data-placement-id="notice_strip" data-revision="${escapeHtml(noticeStrip.content_revision)}">
          <div class="container notice-strip__inner">
            <span><strong>${escapeHtml(noticeStrip.heading)}:</strong> ${escapeHtml(noticeStrip.summary)}</span>
            <a href="${escapeHtml(noticeStrip.cta_destination)}" data-campaign-cta="notice_strip">${escapeHtml(noticeStrip.cta_label)}</a>
          </div>
        </div>`
      : ''
  }

  <header class="site-header">
    <div class="container site-header__inner">
      <a href="/" class="brand-lockup">
        <img src="/assets/brand-mark.svg" alt="" width="38" height="38" aria-hidden="true">
        <span class="brand-lockup__text">
          <span class="brand-lockup__name">${escapeHtml(settings.trading_name)}</span>
          <span class="brand-lockup__sub">Commercial Property Care</span>
        </span>
      </a>

      <button type="button" class="nav-toggle" id="nav-toggle" aria-expanded="false" aria-controls="primary-navigation">
        Menu
      </button>

      <nav id="primary-navigation" class="primary-nav" aria-label="Primary">
        <ul class="primary-nav__list">
          ${navItems
            .map((item) => {
              const isCurrent = currentPath === item.href || (item.children && item.children.some((c) => currentPath === c.href));
              if (item.children && item.children.length > 0) {
                return `<li class="nav-item-dropdown">
                  <a href="${escapeHtml(item.href)}" class="primary-nav__link primary-nav__link--has-dropdown"${
                    isCurrent ? ' aria-current="page"' : ''
                  }>
                    ${escapeHtml(item.label)}
                    <svg class="dropdown-icon" width="12" height="12" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/>
                    </svg>
                  </a>
                  <ul class="nav-dropdown-menu" aria-label="${escapeHtml(item.label)} Submenu">
                    ${item.children
                      .map(
                        (sub) => `<li><a href="${escapeHtml(sub.href)}" class="nav-dropdown-item"${
                          currentPath === sub.href ? ' aria-current="page"' : ''
                        }>${escapeHtml(sub.label)}</a></li>`
                      )
                      .join('')}
                  </ul>
                </li>`;
              }
              return `<li><a href="${escapeHtml(item.href)}" class="primary-nav__link"${
                isCurrent ? ' aria-current="page"' : ''
              }>${escapeHtml(item.label)}</a></li>`;
            })
            .join('')}
          <li class="mobile-only-nav mobile-nav-divider" aria-hidden="true"></li>
          <li class="mobile-only-nav"><a href="/request-service/" class="primary-nav__link">Existing Customer Service</a></li>
          <li class="mobile-only-nav"><a href="/contact/" class="primary-nav__link">Contact Us</a></li>
          <li class="mobile-only-nav mobile-nav-hours">
            <span>Greater Phoenix, AZ</span>
            <span class="muted">${escapeHtml(settings.hours_display)}</span>
          </li>
          <li class="mobile-only-nav mobile-nav-action">
            <a href="/request-proposal/" class="btn btn--primary" style="width:100%;justify-content:center;">Request a Proposal</a>
          </li>
        </ul>
      </nav>

      <div class="site-header__actions">
        <!-- Direct Location & Operating Hours Indicator -->
        <details class="header-info-dropdown" id="header-info-menu">
          <summary class="header-info-trigger" aria-label="Location, hours, and direct support links">
            <span class="header-info-pill">Phoenix, AZ</span>
            <svg class="dropdown-icon" width="12" height="12" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/>
            </svg>
          </summary>
          <div class="header-info-popover">
            <div class="header-info-item">
              <strong>Coverage Area:</strong> Greater Phoenix, AZ
            </div>
            <div class="header-info-item">
              <strong>Operating Hours:</strong> ${escapeHtml(settings.hours_display)}
            </div>
            <hr class="header-info-divider">
            <ul class="header-info-links">
              <li><a href="/request-service/">Existing Customer Service &rarr;</a></li>
              <li><a href="/contact/">Direct Contact &amp; Licensing &rarr;</a></li>
            </ul>
          </div>
        </details>

        <a href="tel:${escapeHtml(settings.phone_e164)}" data-track="phone_click" class="header-phone">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
          </svg>
          <span>${escapeHtml(settings.phone_display)}</span>
        </a>
      </div>
    </div>
  </header>

  <main id="main-content" tabindex="-1">
    ${bodyHtml}
  </main>

  ${
    hideStickyCta
      ? ''
      : `<div class="mobile-sticky-cta" aria-label="Quick actions">
          <a href="tel:${escapeHtml(settings.phone_e164)}" class="btn btn--secondary" data-track="phone_click">Call ${escapeHtml(settings.phone_display)}</a>
          <a href="/request-proposal/" class="btn btn--primary">Request a proposal</a>
        </div>`
  }

  <footer class="site-footer">
    <div class="container">
      <div class="footer-grid footer-grid--ref">
        <div>
          <div class="footer-brand-row">
            <img src="/assets/brand-mark.svg" alt="" width="34" height="34" aria-hidden="true">
            <div>
              <h2 class="footer-heading" style="margin-bottom:0.1rem;">${escapeHtml(settings.trading_name)}</h2>
              <span class="footer-sub">Commercial Property Care</span>
            </div>
          </div>
          <p>${escapeHtml(settings.trading_name)} is the trading name of <strong>${escapeHtml(settings.legal_entity)}</strong>. Commercial recurring care, repairs, and tenant improvements across Greater Phoenix.</p>
        </div>

        <div>
          <h2 class="footer-heading">Services</h2>
          <ul class="footer-links">
            <li><a href="/services/day-porter/">Day Porter Services</a></li>
            <li><a href="/services/recurring-property-care/">Recurring Property Care</a></li>
            <li><a href="/services/commercial-maintenance/">Commercial Maintenance</a></li>
            <li><a href="/services/warehouse-repairs/">Warehouse Repairs</a></li>
            <li><a href="/services/tenant-improvements/">Tenant Improvements</a></li>
            <li><a href="/services/">All Services</a></li>
          </ul>
        </div>

        <div>
          <h2 class="footer-heading">Properties We Serve</h2>
          <ul class="footer-links">
            <li><a href="/properties/industrial-warehouses/">Industrial &amp; Warehouses</a></li>
            <li><a href="/properties/retail-centers/">Retail Centers</a></li>
            <li><a href="/properties/commercial-offices/">Commercial Offices</a></li>
            <li><a href="/property-managers/">Property Managers</a></li>
            <li><a href="/service-area/">Greater Phoenix Service Area</a></li>
          </ul>
        </div>

        <div>
          <h2 class="footer-heading">Company &amp; Resources</h2>
          <ul class="footer-links">
            <li><a href="/about/">About Us (Roots to 1989)</a></li>
            <li><a href="/projects/">Completed Projects</a></li>
            <li><a href="/credentials/">Credentials &amp; ROC Licenses</a></li>
            <li><a href="/credentials/capabilities.pdf" download="Service-Maintenance-Capabilities.pdf" data-track="download_capabilities">Capabilities Statement (PDF)</a></li>
            <li><a href="/careers/">Careers &amp; Openings</a></li>
            ${hasPublishedInsights ? '<li><a href="/insights/">Insights</a></li>' : ''}
            <li><a href="/privacy/">Privacy Policy</a></li>
            <li><a href="/accessibility/">Accessibility</a></li>
            <li><button type="button" class="btn btn--ghost-light" id="open-consent-dialog" style="margin-top:0.5rem;padding:0.4rem 0.75rem;font-size:0.85rem;">Cookie &amp; Privacy Choices</button></li>
          </ul>
        </div>

        <div>
          <h2 class="footer-heading">Contact</h2>
          <ul class="footer-links">
            <li><a href="tel:${escapeHtml(settings.phone_e164)}" data-track="phone_click">${escapeHtml(settings.phone_display)}</a></li>
            <li><a href="mailto:${escapeHtml(settings.monitored_inbox)}" data-track="email_click">${escapeHtml(settings.monitored_inbox)}</a></li>
            <li>${escapeHtml(formatPublicAddress(settings.address_display))}</li>
            <li>${escapeHtml(settings.hours_display)}</li>
            <li><a href="/request-proposal/">Request a Proposal</a></li>
            <li><a href="/request-service/">Existing Customer Service</a></li>
          </ul>
        </div>
      </div>

      <div class="footer-bottom">
        <span>&copy; ${currentYear} ${escapeHtml(settings.legal_entity)} dba ${escapeHtml(settings.trading_name)}. All rights reserved.</span>
        <span>${escapeHtml(settings.roc_numbers)} | <a href="https://roc.az.gov/" rel="noopener noreferrer" target="_blank">Verify Arizona ROC Status</a> | License badges do not imply all trades are self-performed.</span>
      </div>
    </div>
  </footer>

  ${
    consentState === 'undecided'
      ? `<aside class="consent-bar" id="consent-banner" aria-label="Cookie and analytics preferences">
          <div class="consent-bar__inner">
            <p style="margin:0;font-size:0.9rem;color:#F4F0E8;">
              We use strictly necessary storage for security and form reliability. Optional first-party analytics remain off until you choose. <a href="/privacy/" style="color:#F4F0E8;">Privacy policy</a>.
            </p>
            <div class="consent-bar__actions">
              <button type="button" class="btn btn--ghost-light" data-consent-action="essential_only">Reject Optional</button>
              <button type="button" class="btn btn--secondary" style="background:#E4DCCE;border-color:#E4DCCE;" id="consent-customize-btn">Preferences</button>
              <button type="button" class="btn btn--primary" data-consent-action="analytics_accepted">Accept Analytics</button>
            </div>
          </div>
        </aside>`
      : ''
  }

  <dialog id="consent-dialog" closedby="any" aria-labelledby="consent-dialog-title">
    <h2 id="consent-dialog-title">Privacy &amp; Cookie Preferences</h2>
    <p>Inquiries and job applications always work with optional analytics disabled. Choose whether to allow non-identifying first-party page/service interaction metrics.</p>
    <form method="dialog" id="consent-dialog-form">
      <fieldset class="choice-group">
        <legend>Consent Categories</legend>
        <div class="choice-row">
          <input type="checkbox" id="consent-essential" checked disabled>
          <label for="consent-essential"><strong>Strictly Necessary</strong> — Security, CSRF, session, and durable form submission (always active).</label>
        </div>
        <div class="choice-row">
          <input type="checkbox" id="consent-analytics" name="analytics"${consentState === 'analytics_accepted' ? ' checked' : ''}>
          <label for="consent-analytics"><strong>Optional Non-Identifying Analytics</strong> — Service/campaign engagement counts stripped of names, emails, phones, and filenames.</label>
        </div>
      </fieldset>
      <div style="display:flex;gap:0.75rem;flex-wrap:wrap;justify-content:flex-end;">
        <button type="button" class="btn btn--secondary" id="consent-close-btn">Cancel</button>
        <button type="submit" class="btn btn--primary" value="save">Save Preferences</button>
      </div>
    </form>
  </dialog>

  ${previewInfo?.viewport === 'mobile' ? '</div>' : ''}
  <div id="live-announcer" aria-live="polite" class="visually-hidden"></div>
  <script nonce="${escapeHtml(nonce)}" src="/js/app.js?v=${ASSET_VERSION}" defer></script>
</body>
</html>`;
}
