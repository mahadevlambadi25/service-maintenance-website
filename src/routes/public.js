import fs from 'node:fs';
import path from 'node:path';
import { ENV, ROOT_DIR, STORAGE_PATHS } from '../config.js';
import { randomToken } from '../lib/crypto.js';
import { generateCapabilitiesPdf } from '../lib/pdf-generator.js';
import { escapeHtml } from '../lib/sanitize.js';
import { resolveActiveCampaigns } from '../services/campaign-engine.js';
import { parseCookies } from '../services/auth.js';
import { buildJsonLdBreadcrumbs, renderPublicLayout } from '../views/layout.js';
import * as Pages from '../views/public-pages.js';
import { createObjectStore } from '../services/object-store.js';

export async function getCanonicalSettings(db) {
  return db.prepare('SELECT * FROM business_settings WHERE id = 1').get();
}

async function getPublishedRevision(db, page) {
  if (!page || !page.published_revision) return null;
  return db
    .prepare('SELECT * FROM page_revisions WHERE page_id = ? AND revision_number = ?')
    .get(page.page_id, page.published_revision);
}

function sendHtml(res, statusCode, html, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'public, max-age=60, must-revalidate',
    ...headers,
  });
  res.end(html);
}

async function getApprovedProjectsList(db, { service = '', property = '' } = {}) {
  let rows = await db
    .prepare(
      `SELECT p.*, m.public_derivative_key as cover_derivative_key, m.variants_json as cover_variants_json, m.alt_text as cover_alt, m.focal_x as cover_focal_x, m.focal_y as cover_focal_y
       FROM projects p
       LEFT JOIN media_assets m ON m.asset_id = p.cover_asset_id AND m.rights_status = 'approved'
       WHERE p.editorial_state = 'Approved' AND p.activation_state = 'Live' AND p.is_private_test = 0
       ORDER BY p.featured_on_home DESC, p.featured_order ASC, p.completion_date DESC`
    )
    .all();

  if (service) {
    rows = rows.filter((r) => {
      try {
        return JSON.parse(r.related_services_json || '[]').includes(service);
      } catch {
        return false;
      }
    });
  }
  if (property) {
    rows = rows.filter((r) => r.property_type === property);
  }
  return rows;
}

function getConsentFromReq(req) {
  const cookies = parseCookies(req);
  const c = cookies.sm_consent;
  if (c === 'analytics_accepted' || c === 'essential_only') return c;
  return 'undecided';
}

export async function handlePublicRoute(req, res, db, urlObj, nonce, storagePaths = STORAGE_PATHS) {
  const pathname = urlObj.pathname;
  const settings = await getCanonicalSettings(db);
  const consentState = getConsentFromReq(req);

  // 1. Static files under /css, /js, /assets
  if (pathname.startsWith('/css/') || pathname.startsWith('/js/') || pathname.startsWith('/assets/')) {
    const safeRel = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
    const fullPath = path.join(ROOT_DIR, 'public', safeRel);
    if (fullPath.startsWith(path.join(ROOT_DIR, 'public')) && fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      const ext = path.extname(fullPath).toLowerCase();
      const mimeMap = {
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.webp': 'image/webp',
      };
      res.writeHead(200, {
        'Content-Type': mimeMap[ext] || 'application/octet-stream',
        'Cache-Control': 'public, max-age=3600',
      });
      fs.createReadStream(fullPath).pipe(res);
      return true;
    }
  }

  // 1b. Favicon route (serve brand mark SVG so browsers never log /favicon.ico 404 console errors)
  if (pathname === '/favicon.ico') {
    const iconPath = path.join(ROOT_DIR, 'public', 'assets', 'brand-mark.svg');
    if (fs.existsSync(iconPath) && fs.statSync(iconPath).isFile()) {
      res.writeHead(200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'public, max-age=86400',
      });
      fs.createReadStream(iconPath).pipe(res);
      return true;
    }
  }

  // 2. Approved Public Media Derivatives ONLY (/media/<key>) — private originals & unapproved assets NEVER served!
  if (pathname.startsWith('/media/')) {
    const key = path.basename(pathname.slice('/media/'.length));
    const candidate = await db
      .prepare(
        `SELECT * FROM media_assets
         WHERE is_public_published = 1
           AND rights_status = 'approved'
           AND (public_derivative_key = ? OR variants_json LIKE ?)`
      )
      .get(key, `%${key}%`);
    let matchedAsset = null;
    if (candidate) {
      if (candidate.public_derivative_key === key) {
        matchedAsset = candidate;
      } else if (candidate.variants_json) {
        try {
          const parsed = JSON.parse(candidate.variants_json);
          const allVariantKeys = [...Object.values(parsed.webp || {}), ...Object.values(parsed.jpeg || {})];
          if (allVariantKeys.includes(key)) matchedAsset = candidate;
        } catch {}
      }
    }
    if (!matchedAsset) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return true;
    }
    const store = createObjectStore(storagePaths);
    const mediaBuf = await store.getObjectBuffer({ area: 'publicMedia', key });
    if (!mediaBuf) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return true;
    }
    const respMime = key.endsWith('.webp') ? 'image/webp' : key.endsWith('.jpg') || key.endsWith('.jpeg') ? 'image/jpeg' : matchedAsset.derivative_mime || 'image/jpeg';
    res.writeHead(200, {
      'Content-Type': respMime,
      'Content-Length': mediaBuf.length,
      'Cache-Control': 'public, max-age=300, must-revalidate',
    });
    res.end(mediaBuf);
    return true;
  }

  // 3. Legacy Redirects & Trailing Slash Normalization (PRD 14.02 & 23.01)
  const redirectRow = await db
    .prepare('SELECT * FROM redirects WHERE old_path = ? AND active = 1')
    .get(pathname);
  if (redirectRow) {
    res.writeHead(redirectRow.status_code || 301, { Location: redirectRow.destination_path });
    res.end();
    return true;
  }

  // 4. Special Technical SEO & Procurement Endpoints
  if (pathname === '/robots.txt') {
    const lines = ENV.IS_STAGING
      ? ['User-agent: *', 'Disallow: /']
      : [
          'User-agent: *',
          'Allow: /',
          'Disallow: /admin/',
          'Disallow: /api/',
          `Sitemap: ${ENV.BASE_URL}/sitemap.xml`,
        ];
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(lines.join('\n') + '\n');
    return true;
  }

  if (pathname === '/sitemap.xml') {
    if (ENV.IS_STAGING) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not available on staging');
      return true;
    }
    const urls = [];
    const livePages = await db
      .prepare(
        `SELECT slug, updated_at FROM pages
         WHERE editorial_state = 'Approved' AND activation_state = 'Live' AND indexable = 1`
      )
      .all();
    for (const p of livePages) {
      urls.push({ loc: `${ENV.BASE_URL}${p.slug}`, lastmod: p.updated_at.slice(0, 10) });
    }
    // Permanent launch routes
    urls.push({ loc: `${ENV.BASE_URL}/projects/`, lastmod: new Date().toISOString().slice(0, 10) });
    urls.push({ loc: `${ENV.BASE_URL}/careers/`, lastmod: new Date().toISOString().slice(0, 10) });

    const liveProjects = await db
      .prepare(
        `SELECT slug, updated_at FROM projects
         WHERE editorial_state = 'Approved' AND activation_state = 'Live' AND is_private_test = 0`
      )
      .all();
    for (const pr of liveProjects) {
      urls.push({ loc: `${ENV.BASE_URL}/projects/${pr.slug}/`, lastmod: pr.updated_at.slice(0, 10) });
    }

    const openJobs = await db
      .prepare(`SELECT slug, updated_at FROM jobs WHERE status = 'Open' AND is_private_test = 0`)
      .all();
    for (const j of openJobs) {
      urls.push({ loc: `${ENV.BASE_URL}/careers/${j.slug}/`, lastmod: j.updated_at.slice(0, 10) });
    }

    const liveArticles = await db
      .prepare(`SELECT slug, updated_at FROM articles WHERE editorial_state = 'Approved' AND activation_state = 'Live'`)
      .all();
    if (liveArticles.length > 0) {
      urls.push({ loc: `${ENV.BASE_URL}/insights/`, lastmod: new Date().toISOString().slice(0, 10) });
      for (const a of liveArticles) {
        urls.push({ loc: `${ENV.BASE_URL}/insights/${a.slug}/`, lastmod: a.updated_at.slice(0, 10) });
      }
    }

    const liveCampaignLps = await db
      .prepare(
        `SELECT slug, updated_at FROM campaigns
         WHERE editorial_state = 'Approved' AND activation_state = 'Live'
           AND landing_page_enabled = 1 AND landing_page_noindex = 0`
      )
      .all();
    for (const lp of liveCampaignLps) {
      urls.push({ loc: `${ENV.BASE_URL}/lp/${lp.slug}/`, lastmod: lp.updated_at.slice(0, 10) });
    }

    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls
      .map((u) => `  <url><loc>${escapeHtml(u.loc)}</loc><lastmod>${escapeHtml(u.lastmod)}</lastmod></url>`)
      .join('\n')}\n</urlset>\n`;
    res.writeHead(200, { 'Content-Type': 'application/xml; charset=utf-8' });
    res.end(xml);
    return true;
  }

  if (pathname === '/credentials/capabilities.pdf') {
    const pdfBuf = generateCapabilitiesPdf(settings);
    res.writeHead(200, {
      'Content-Type': 'application/pdf',
      'Content-Disposition': 'inline; filename="Service-Maintenance-Capabilities.pdf"',
      'Content-Length': pdfBuf.length,
    });
    res.end(pdfBuf);
    return true;
  }

  // Common runtime context for public pages
  const activeCampaigns = await resolveActiveCampaigns(db);
  const publishedInsightsRow = await db
    .prepare(`SELECT COUNT(*) as cnt FROM articles WHERE editorial_state = 'Approved' AND activation_state = 'Live'`)
    .get();
  const publishedInsightsCount = publishedInsightsRow?.cnt || 0;
  const hasPublishedInsights = publishedInsightsCount > 0;
  const buildingEngineerPage = await db.prepare(`SELECT * FROM pages WHERE slug = '/services/building-engineer/'`).get();
  const buildingEngineerLive = Boolean(
    buildingEngineerPage &&
      buildingEngineerPage.editorial_state === 'Approved' &&
      buildingEngineerPage.activation_state === 'Live'
  );
  const formCsrf = randomToken(16);

  const renderPageShell = (opts) =>
    renderPublicLayout({
      settings,
      noticeStrip: activeCampaigns.noticeStrip,
      hasPublishedInsights,
      nonce,
      consentState,
      currentPath: pathname,
      ...opts,
    });

  // 5. CMS-Backed Standard Pages
  const page = await db
    .prepare(`SELECT * FROM pages WHERE slug = ? AND editorial_state = 'Approved' AND activation_state = 'Live'`)
    .get(pathname);

  if (page) {
    const rev = await getPublishedRevision(db, page);
    if (rev) {
      if (page.template === 'home') {
        const approvedProjects = await getApprovedProjectsList(db);
        const html = renderPageShell({
          title: rev.meta_title,
          metaDescription: rev.meta_description,
          canonicalPath: '/',
          bodyHtml: Pages.renderHomePage({
            rev,
            settings,
            approvedProjects,
            seasonalFeature: activeCampaigns.homepageFeature,
            buildingEngineerLive,
          }),
        });
        sendHtml(res, 200, html);
        return true;
      }

      if (page.template === 'service_overview') {
        const html = renderPageShell({
          title: rev.meta_title,
          metaDescription: rev.meta_description,
          canonicalPath: page.slug,
          extraJsonLd: [buildJsonLdBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Services', href: '/services/' }])],
          bodyHtml: Pages.renderServiceOverviewPage({ buildingEngineerLive }),
        });
        sendHtml(res, 200, html);
        return true;
      }

      if (page.template === 'service') {
        const relatedProjects = await getApprovedProjectsList(db, { service: page.service_family || '' });
        const contextualCampaign = activeCampaigns.serviceModules.get(page.slug) || null;
        const html = renderPageShell({
          title: rev.meta_title,
          metaDescription: rev.meta_description,
          canonicalPath: page.slug,
          extraJsonLd: [
            buildJsonLdBreadcrumbs([
              { label: 'Home', href: '/' },
              { label: 'Services', href: '/services/' },
              { label: rev.title, href: page.slug },
            ]),
            {
              '@context': 'https://schema.org',
              '@type': 'Service',
              name: rev.title,
              provider: { '@type': 'LocalBusiness', name: settings.trading_name },
              areaServed: 'Greater Phoenix, Arizona',
              description: rev.meta_description,
            },
          ],
          bodyHtml: Pages.renderServiceDetailPage({ page, rev, contextualCampaign, relatedProjects, settings }),
        });
        sendHtml(res, 200, html);
        return true;
      }

      if (page.template === 'property_overview' || page.template === 'property' || page.template === 'buyer_solution') {
        const html = renderPageShell({
          title: rev.meta_title,
          metaDescription: rev.meta_description,
          canonicalPath: page.slug,
          extraJsonLd: [
            buildJsonLdBreadcrumbs([
              { label: 'Home', href: '/' },
              { label: 'Properties we serve', href: '/properties/' },
              ...(page.slug === '/properties/' ? [] : [{ label: rev.title, href: page.slug }]),
            ]),
          ],
          bodyHtml: Pages.renderPropertyPage({ page, rev }),
        });
        sendHtml(res, 200, html);
        return true;
      }

      if (page.template === 'company') {
        sendHtml(
          res,
          200,
          renderPageShell({
            title: rev.meta_title,
            metaDescription: rev.meta_description,
            canonicalPath: page.slug,
            bodyHtml: Pages.renderAboutPage({ settings }),
          })
        );
        return true;
      }

      if (page.template === 'procurement') {
        sendHtml(
          res,
          200,
          renderPageShell({
            title: rev.meta_title,
            metaDescription: rev.meta_description,
            canonicalPath: page.slug,
            bodyHtml: Pages.renderCredentialsPage({ settings }),
          })
        );
        return true;
      }

      if (page.template === 'geography') {
        sendHtml(
          res,
          200,
          renderPageShell({
            title: rev.meta_title,
            metaDescription: rev.meta_description,
            canonicalPath: page.slug,
            bodyHtml: Pages.renderServiceAreaPage({ settings }),
          })
        );
        return true;
      }

      if (page.template === 'contact') {
        sendHtml(
          res,
          200,
          renderPageShell({
            title: rev.meta_title,
            metaDescription: rev.meta_description,
            canonicalPath: page.slug,
            bodyHtml: Pages.renderContactPage({ settings }),
          })
        );
        return true;
      }

      if (page.template === 'policy') {
        sendHtml(
          res,
          200,
          renderPageShell({
            title: rev.meta_title,
            metaDescription: rev.meta_description,
            canonicalPath: page.slug,
            bodyHtml: `<section class="section"><div class="container"><h1>${escapeHtml(rev.hero_headline)}</h1><p class="muted">${escapeHtml(rev.hero_summary)}</p>${rev.body_html}</div></section>`,
          })
        );
        return true;
      }
    }
  }

  // 6. Forms & Confirmation Pages
  if (pathname === '/request-proposal/') {
    const preselectedService = urlObj.searchParams.get('service') || '';
    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Request a Proposal | Service Maintenance',
        metaDescription: 'Submit a commercial maintenance, day porter, warehouse repair, or tenant improvement inquiry for Greater Phoenix.',
        canonicalPath: '/request-proposal/',
        hideStickyCta: true,
        bodyHtml: Pages.renderProposalFormPage({ preselectedService, settings, csrfToken: formCsrf }),
      })
    );
    return true;
  }

  if (pathname === '/request-service/') {
    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Existing Customer Service Request | Service Maintenance',
        metaDescription: 'Route an active commercial account maintenance or property care request to our operations team.',
        canonicalPath: '/request-service/',
        hideStickyCta: true,
        bodyHtml: Pages.renderServiceRequestFormPage({ settings, csrfToken: formCsrf }),
      })
    );
    return true;
  }

  if (pathname === '/thank-you/') {
    const refId = urlObj.searchParams.get('ref') || '';
    const kind = urlObj.searchParams.get('kind') || 'new_business';
    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Request Received | Service Maintenance',
        metaDescription: 'Inquiry confirmation.',
        canonicalPath: '/thank-you/',
        noindex: true,
        hideStickyCta: true,
        bodyHtml: Pages.renderThankYouPage({ receiptId: refId, kind, settings }),
      })
    );
    return true;
  }

  // 7. Projects Archive & Detail (Permanent route with truthful empty state)
  if (pathname === '/projects/') {
    const filterService = urlObj.searchParams.get('service') || '';
    const filterProperty = urlObj.searchParams.get('property') || '';
    const allLive = await getApprovedProjectsList(db);
    const availableServices = Array.from(
      new Set(allLive.flatMap((p) => { try { return JSON.parse(p.related_services_json || '[]'); } catch { return []; } }))
    );
    const availableProperties = Array.from(new Set(allLive.map((p) => p.property_type).filter(Boolean)));
    const filtered = await getApprovedProjectsList(db, { service: filterService, property: filterProperty });

    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Completed Projects | Service Maintenance',
        metaDescription: 'Approved commercial maintenance, repair, and tenant improvement projects completed across Greater Phoenix.',
        canonicalPath: '/projects/',
        bodyHtml: Pages.renderProjectsArchivePage({
          projects: filtered,
          filterService,
          filterProperty,
          availableServices,
          availableProperties,
        }),
      })
    );
    return true;
  }

  const projectMatch = pathname.match(/^\/projects\/([a-z0-9-]+)\/$/);
  if (projectMatch) {
    const slug = projectMatch[1];
    const project = await db
      .prepare(
        `SELECT p.*, m.public_derivative_key as cover_derivative_key, m.variants_json as cover_variants_json, m.alt_text as cover_alt, m.focal_x as cover_focal_x, m.focal_y as cover_focal_y
         FROM projects p
         LEFT JOIN media_assets m ON m.asset_id = p.cover_asset_id AND m.rights_status = 'approved' AND m.is_public_published = 1
         WHERE p.slug = ? AND p.editorial_state = 'Approved' AND p.activation_state = 'Live' AND p.is_private_test = 0`
      )
      .get(slug);
    if (project) {
      const pairs = await db
        .prepare(
          `SELECT p.*,
                  b.public_derivative_key as before_derivative_key, b.variants_json as before_variants_json, b.width as before_width, b.height as before_height, b.focal_x as before_focal_x, b.focal_y as before_focal_y, b.rights_status as before_rights,
                  a.public_derivative_key as after_derivative_key, a.variants_json as after_variants_json, a.width as after_width, a.height as after_height, a.focal_x as after_focal_x, a.focal_y as after_focal_y, a.rights_status as after_rights
           FROM project_before_after_pairs p
           JOIN media_assets b ON b.asset_id = p.before_asset_id
           JOIN media_assets a ON a.asset_id = p.after_asset_id
           WHERE p.project_id = ? AND b.rights_status = 'approved' AND a.rights_status = 'approved'
           ORDER BY p.sort_order ASC`
        )
        .all(project.project_id);

      const gallery = await db
        .prepare(
          `SELECT g.*, m.public_derivative_key, m.variants_json, m.width, m.height, m.focal_x, m.focal_y
           FROM project_gallery_items g
           JOIN media_assets m ON m.asset_id = g.asset_id
           WHERE g.project_id = ? AND m.rights_status = 'approved' AND m.is_public_published = 1
           ORDER BY g.sort_order ASC`
        )
        .all(project.project_id);

      sendHtml(
        res,
        200,
        renderPageShell({
          title: project.meta_title || `${project.title} | Service Maintenance`,
          metaDescription: project.meta_description || project.agreed_scope,
          canonicalPath: `/projects/${project.slug}/`,
          bodyHtml: Pages.renderProjectDetailPage({ project, pairs, gallery }),
        })
      );
      return true;
    }
  }

  // 8. Insights Archive & Detail (Conditional: visible only when approved live articles exist)
  if (pathname === '/insights/' && hasPublishedInsights) {
    const articles = await db
      .prepare(`SELECT * FROM articles WHERE editorial_state = 'Approved' AND activation_state = 'Live' ORDER BY published_at DESC`)
      .all();
    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Insights | Service Maintenance',
        metaDescription: 'Practical commercial property maintenance, day porter, and tenant improvement guides.',
        canonicalPath: '/insights/',
        bodyHtml: Pages.renderInsightsArchivePage({ articles }),
      })
    );
    return true;
  }

  const articleMatch = pathname.match(/^\/insights\/([a-z0-9-]+)\/$/);
  if (articleMatch) {
    const article = await db
      .prepare(`SELECT * FROM articles WHERE slug = ? AND editorial_state = 'Approved' AND activation_state = 'Live'`)
      .get(articleMatch[1]);
    if (article) {
      sendHtml(
        res,
        200,
        renderPageShell({
          title: `${article.title} | Insights | Service Maintenance`,
          metaDescription: article.summary,
          canonicalPath: `/insights/${article.slug}/`,
          bodyHtml: Pages.renderArticleDetailPage({ article }),
        })
      );
      return true;
    }
  }

  // 9. Campaign Landing Pages (/lp/{campaign}/)
  const lpMatch = pathname.match(/^\/lp\/([a-z0-9-]+)\/$/);
  if (lpMatch) {
    const camp = await db.prepare(`SELECT * FROM campaigns WHERE slug = ? AND landing_page_enabled = 1`).get(lpMatch[1]);
    if (camp && camp.editorial_state === 'Approved') {
      const nowMs = Date.now();
      const startMs = new Date(camp.start_at).getTime();
      const endMs = camp.is_evergreen ? Number.POSITIVE_INFINITY : new Date(camp.end_at || 0).getTime();
      const isLive = camp.activation_state === 'Live' && nowMs >= startMs && nowMs < endMs;

      if (!isLive && camp.landing_expiry_policy === 'redirect' && camp.landing_expiry_redirect) {
        res.writeHead(302, { Location: camp.landing_expiry_redirect });
        res.end();
        return true;
      }

      if (camp.asset_id) {
        const asset = await db
          .prepare(`SELECT asset_id, public_derivative_key, alt_text, width, height, focal_x, focal_y, expiry_date FROM media_assets WHERE asset_id = ? AND rights_status = 'approved'`)
          .get(camp.asset_id);
        if (asset && (!asset.expiry_date || new Date(asset.expiry_date).getTime() > nowMs)) {
          camp.asset = asset;
        }
      }

      sendHtml(
        res,
        200,
        renderPageShell({
          title: `${camp.heading} | Service Maintenance`,
          metaDescription: camp.summary,
          canonicalPath: `/lp/${camp.slug}/`,
          noindex: Boolean(camp.landing_page_noindex) || !isLive,
          bodyHtml: Pages.renderCampaignLandingPage({ campaign: camp, expired: !isLive && camp.landing_expiry_policy !== 'evergreen' }),
        })
      );
      return true;
    }
  }

  // 10. Careers & Protected Application Flow (Permanent launch routes)
  if (pathname === '/careers/') {
    const openJobs = await db
      .prepare(`SELECT * FROM jobs WHERE status = 'Open' AND is_private_test = 0 ORDER BY updated_at DESC`)
      .all();
    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Careers & Current Openings | Service Maintenance',
        metaDescription: 'Explore current commercial maintenance, day porter, and project openings at Service Maintenance in Greater Phoenix.',
        canonicalPath: '/careers/',
        bodyHtml: Pages.renderCareersOverviewPage({ openJobs, settings }),
      })
    );
    return true;
  }

  if (pathname === '/application-received/') {
    const refId = urlObj.searchParams.get('ref') || '';
    const roleTitle = urlObj.searchParams.get('role') || '';
    const attachmentState = urlObj.searchParams.get('att') || '';
    sendHtml(
      res,
      200,
      renderPageShell({
        title: 'Application Received | Service Maintenance',
        metaDescription: 'Application confirmation.',
        canonicalPath: '/application-received/',
        noindex: true,
        hideStickyCta: true,
        bodyHtml: Pages.renderApplicationReceivedPage({ refId, roleTitle, attachmentState, settings }),
      })
    );
    return true;
  }

  const jobApplyMatch = pathname.match(/^\/careers\/([a-z0-9-]+)\/apply\/$/);
  if (jobApplyMatch) {
    const job = await db.prepare(`SELECT * FROM jobs WHERE slug = ? AND status != 'Draft' AND status != 'Archived'`).get(jobApplyMatch[1]);
    if (job) {
      sendHtml(
        res,
        200,
        renderPageShell({
          title: `Apply: ${job.title} | Careers | Service Maintenance`,
          metaDescription: `Submit an application for ${job.title} (${job.work_area}).`,
          canonicalPath: `/careers/${job.slug}/apply/`,
          noindex: job.status !== 'Open',
          hideStickyCta: true,
          bodyHtml: Pages.renderJobApplyPage({ job, settings, csrfToken: formCsrf }),
        })
      );
      return true;
    }
  }

  const jobDetailMatch = pathname.match(/^\/careers\/([a-z0-9-]+)\/$/);
  if (jobDetailMatch) {
    const job = await db.prepare(`SELECT * FROM jobs WHERE slug = ? AND status != 'Draft' AND status != 'Archived'`).get(jobDetailMatch[1]);
    if (job) {
      const extraJsonLd = [
        buildJsonLdBreadcrumbs([
          { label: 'Home', href: '/' },
          { label: 'Careers', href: '/careers/' },
          { label: job.title, href: `/careers/${job.slug}/` },
        ]),
      ];
      // Google JobPosting structured data ONLY on single Open job pages (PRD Section 17.03)
      if (job.status === 'Open' && !job.is_private_test) {
        extraJsonLd.push({
          '@context': 'https://schema.org',
          '@type': 'JobPosting',
          title: job.title,
          description: job.responsibilities_html.replace(/<[^>]+>/g, ' ').trim(),
          datePosted: (job.publish_at || job.updated_at).slice(0, 10),
          ...(job.close_at ? { validThrough: job.close_at } : {}),
          employmentType: job.employment_type.toUpperCase().replace('-', '_'),
          hiringOrganization: {
            '@type': 'Organization',
            name: settings.trading_name,
            sameAs: ENV.BASE_URL,
          },
          jobLocation: {
            '@type': 'Place',
            address: {
              '@type': 'PostalAddress',
              addressLocality: 'Phoenix',
              addressRegion: 'AZ',
              addressCountry: 'US',
            },
          },
        });
      }
      sendHtml(
        res,
        200,
        renderPageShell({
          title: `${job.title} | Careers | Service Maintenance`,
          metaDescription: `${job.title} — ${job.work_area} (${job.employment_type}).`,
          canonicalPath: `/careers/${job.slug}/`,
          extraJsonLd,
          bodyHtml: Pages.renderJobDetailPage({ job, settings }),
        })
      );
      return true;
    }
  }

  // 11. Real HTTP 404
  if (!pathname.startsWith('/admin') && !pathname.startsWith('/api/')) {
    sendHtml(
      res,
      404,
      renderPageShell({
        title: 'Page Not Found (404) | Service Maintenance',
        metaDescription: 'Requested page could not be found.',
        canonicalPath: pathname,
        noindex: true,
        bodyHtml: Pages.renderNotFoundPage({ settings }),
      })
    );
    return true;
  }

  return false;
}
