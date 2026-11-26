import { SERVICE_FAMILIES, PRIVACY_NOTICE_VERSION } from '../config.js';
import { escapeHtml, sanitizeRichHtml } from '../lib/sanitize.js';
import { renderBeforeAfterPair, renderBreadcrumbs, renderResponsivePicture, renderSeasonalFeatureSlot } from './components.js';

export function renderHomePage({ rev, settings, approvedProjects, seasonalFeature, buildingEngineerLive }) {
  // 10-part required sequence (PRD Section 08.01):
  // 1. Header & Hero (solid surface adjacent to architectural diagram, LCP high priority)
  // 2. Service Pillars (Recurring care, Maintenance/repairs, TI)
  // [Optional Seasonal Focus slot]
  // 3. Why clients choose the relationship (4 substantiated differentiators)
  // 4. Selected work (ONLY if approved public projects exist; otherwise truthful factual operating proof)
  // 5. How work is managed (4 steps)
  // 6. Properties served (Warehouse, Retail, Office, Property Managers)
  // 7. Operating practices (Scope clarity, coordination, communication, closeout)
  // 8. Company story (1989 roots + 2020 transition)
  // 9. Proof / Credentials summary (factual proof without fabricated testimonials)
  // 10. Final inquiry CTA + telephone alternative

  return `
  <!-- 1. Hero -->
  <section class="hero" aria-labelledby="hero-title">
    <div class="container hero__grid">
      <div class="hero__content">
        <span class="eyebrow">Commercial Property Services — Greater Phoenix</span>
        <h1 id="hero-title">${escapeHtml(rev.hero_headline)}</h1>
        <p style="font-size:1.15rem;color:var(--color-muted-stone);">${escapeHtml(rev.hero_summary)}</p>
        <div class="hero__actions">
          <a href="${escapeHtml(rev.cta_route)}" class="btn btn--primary">${escapeHtml(rev.cta_label)}</a>
          <a href="/services/" class="btn btn--secondary">Explore our services</a>
        </div>
        <p class="muted" style="margin-top:1.15rem;font-size:0.9rem;margin-bottom:0;">
          Direct office line: <a href="tel:${escapeHtml(settings.phone_e164)}" data-track="phone_click">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)})
        </p>
      </div>
      <div class="hero__media">
        <img src="/assets/hero-architecture.svg"
             alt="Architectural elevation schematic of commercial warehouse, retail, and office property scopes"
             width="640" height="460" fetchpriority="high">
        <p class="hero__caption">Architectural scope schematic across industrial, retail, and office commercial assets. Our roots date to 1989.</p>
      </div>
    </div>
  </section>

  <!-- 2. Three Service Pillars -->
  <section class="section" aria-labelledby="pillars-title">
    <div class="container">
      <span class="eyebrow">Service Architecture</span>
      <h2 id="pillars-title">Three core pillars—plus specialist paths</h2>
      <div class="grid-3" style="margin-top:1.75rem;">
        <article class="editorial-block">
          <h3>Recurring property care</h3>
          <p>For property managers seeking reliable daytime upkeep and predictable exterior schedules.</p>
          <p class="muted" style="font-size:0.93rem;">Day porter services, pressure washing, parking lot sweeping, roof debris observations${buildingEngineerLive ? ', and building engineer support' : ''}.</p>
          <p><a href="/services/day-porter/">Day porter services</a> &middot; <a href="/services/recurring-property-care/">All recurring care</a></p>
        </article>
        <article class="editorial-block">
          <h3>Commercial maintenance &amp; repairs</h3>
          <p>For facilities and operations teams needing clear coordination on routine repairs or multi-item lists.</p>
          <p class="muted" style="font-size:0.93rem;">Interior drywall/paint/doors, warehouse scrim &amp; insulation, bollards, concrete, lighting, plumbing coordination, and site repairs.</p>
          <p><a href="/services/commercial-maintenance/">Commercial maintenance</a> &middot; <a href="/services/warehouse-repairs/">Warehouse repairs</a></p>
        </article>
        <article class="editorial-block">
          <h3>Tenant improvements &amp; make-ready</h3>
          <p>For owners and asset managers planning suite build-outs, alterations, or lease-return turnovers.</p>
          <p class="muted" style="font-size:0.93rem;">Scope planning, selective demolition, framing/finishes, trade and permit coordination, white-shell put-backs, and final cleaning.</p>
          <p><a href="/services/tenant-improvements/">Tenant improvements</a> &middot; <a href="/services/tenant-move-outs/">Tenant move-outs</a></p>
        </article>
      </div>
    </div>
  </section>

  <!-- Optional Configurable Seasonal Focus Placement -->
  ${renderSeasonalFeatureSlot(seasonalFeature)}

  <!-- 3. Why Clients Choose the Relationship -->
  <section class="section section--bone" aria-labelledby="diff-title">
    <div class="container">
      <span class="eyebrow">Accountable Relationship</span>
      <h2 id="diff-title">Why commercial teams work with Service Maintenance</h2>
      <div class="grid-2" style="margin-top:1.5rem;">
        <div class="editorial-block editorial-block--bronze">
          <h3>Care across the property’s lifecycle</h3>
          <p>A working relationship can span daily porter upkeep, targeted repairs, lease turnovers, and larger tenant improvements without changing partners.</p>
        </div>
        <div class="editorial-block editorial-block--bronze">
          <h3>In-house work plus specialty coordination</h3>
          <p>We execute core maintenance, porter programs, and final suite cleaning in-house while coordinating vetted specialty trades transparently where licensing requires.</p>
        </div>
        <div class="editorial-block editorial-block--bronze">
          <h3>Familiarity with operating commercial sites</h3>
          <p>Scopes account for occupied suites, tenant hours, dock deliveries, and safety barricading—without making unrealistic zero-disruption promises.</p>
        </div>
        <div class="editorial-block editorial-block--bronze">
          <h3>Attention to small repairs and larger work</h3>
          <p>Ordinary maintenance tasks receive the same clear scope review and closeout attention as multi-trade commercial improvements.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- 4. Selected Work (Approved projects only; truthful fallback when 0 approved projects exist) -->
  ${
    approvedProjects.length > 0
      ? `<section class="section" aria-labelledby="selected-work-title">
          <div class="container">
            <span class="eyebrow">Completed Work</span>
            <h2 id="selected-work-title">Approved project examples</h2>
            <div class="grid-3" style="margin-top:1.5rem;">
              ${approvedProjects
                .slice(0, 3)
                .map(
                  (proj) => `<article class="panel">
                    ${
                      proj.cover_derivative_key
                        ? renderResponsivePicture({
                            src: `/media/${proj.cover_derivative_key}`,
                            variantsJson: proj.cover_variants_json,
                            alt: proj.cover_alt || proj.title,
                            width: 400,
                            height: 300,
                            focalX: proj.cover_focal_x ?? 50,
                            focalY: proj.cover_focal_y ?? 50,
                            style: 'margin-bottom:1rem;aspect-ratio:4/3;',
                          })
                        : ''
                    }
                    <span class="eyebrow">${escapeHtml(proj.property_type)} &middot; ${escapeHtml(proj.city_region)}</span>
                    <h3><a href="/projects/${escapeHtml(proj.slug)}/">${escapeHtml(proj.title)}</a></h3>
                    <p style="font-size:0.94rem;">${escapeHtml(proj.agreed_scope)}</p>
                  </article>`
                )
                .join('')}
            </div>
            <p style="margin-top:1.5rem;"><a href="/projects/" class="btn btn--secondary">View completed projects</a></p>
          </div>
        </section>`
      : `<section class="section" aria-labelledby="proof-note-title">
          <div class="container">
            <div class="panel">
              <span class="eyebrow">Verified Evidence Standard</span>
              <h2 id="proof-note-title">Real project documentation—never fabricated placeholders</h2>
              <p>Public case studies and before-and-after project records are published on our <a href="/projects/">Projects page</a> only after completion verification and client naming permissions are recorded. Meanwhile, procurement reviewers can inspect our <a href="/credentials/">verified credentials and Capabilities Statement</a>.</p>
            </div>
          </div>
        </section>`
  }

  <!-- 5. How Work Is Managed -->
  <section class="section section--bone" aria-labelledby="process-title">
    <div class="container">
      <span class="eyebrow">Delivery Process</span>
      <h2 id="process-title">How every scope moves from inquiry to closeout</h2>
      <ol class="process-list" style="margin-top:1.75rem;">
        <li class="process-step">
          <span class="process-step__num">01</span>
          <h3>Understand the need</h3>
          <p>Review your property location, operating hours, photos or plans, and approval structure.</p>
        </li>
        <li class="process-step">
          <span class="process-step__num">02</span>
          <h3>Define the scope</h3>
          <p>Confirm in-house tasks, specialty trade participation, access windows, and exclusions in writing.</p>
        </li>
        <li class="process-step">
          <span class="process-step__num">03</span>
          <h3>Coordinate the work</h3>
          <p>Sequence crews, equipment, and site protection around active tenants and deliveries.</p>
        </li>
        <li class="process-step">
          <span class="process-step__num">04</span>
          <h3>Review completion</h3>
          <p>Verify punch items, final cleaning, and closeout documentation with one accountable contact.</p>
        </li>
      </ol>
    </div>
  </section>

  <!-- 6. Properties Served -->
  <section class="section" aria-labelledby="properties-title">
    <div class="container">
      <span class="eyebrow">Operating Environments</span>
      <h2 id="properties-title">Commercial properties we serve</h2>
      <div class="grid-2" style="margin-top:1.5rem;">
        <article class="editorial-block">
          <h3><a href="/properties/industrial-warehouses/">Industrial &amp; warehouse facilities</a></h3>
          <p>Scrim and insulation repair, dock concrete, bollards, welding, and industrial make-ready around active bays.</p>
        </article>
        <article class="editorial-block">
          <h3><a href="/properties/retail-centers/">Retail centers</a></h3>
          <p>Daytime porter routes, common-area presentation, pressure washing, exterior repairs, and inline turnovers.</p>
        </article>
        <article class="editorial-block">
          <h3><a href="/properties/commercial-offices/">Commercial offices &amp; multi-tenant buildings</a></h3>
          <p>Occupied-building repairs, corridor and door upkeep, and phased tenant improvements.</p>
        </article>
        <article class="editorial-block">
          <h3><a href="/property-managers/">Commercial property management portfolios</a></h3>
          <p>Multi-property inquiry routing, consolidated communication, and procurement-ready documentation.</p>
        </article>
      </div>
    </div>
  </section>

  <!-- 7 & 8 & 9. Operating Practices, Story & Credentials Proof -->
  <section class="section section--bone" aria-labelledby="story-title">
    <div class="container grid-2">
      <div>
        <span class="eyebrow">Company Continuity</span>
        <h2 id="story-title">Our roots date to 1989</h2>
        <p>Patrick Voita founded Service Maintenance in 1989 providing day porter services across Greater Phoenix, incorporating in 1992 and expanding into tenant improvements with Greg Vandenberg in 2006. On June 29, 2020, Promptitude Inc. acquired the business to grow commercial maintenance and tenant improvement capabilities while preserving reliable recurring property care.</p>
        <p><a href="/about/">Read our company story and core values</a></p>
      </div>
      <div class="panel panel--light">
        <span class="eyebrow">Verified Credentials &amp; Operating Standards</span>
        <h3>Scope clarity &amp; verified licensing</h3>
        <ul>
          <li><strong>Legal entity:</strong> ${escapeHtml(settings.legal_entity)} dba ${escapeHtml(settings.trading_name)}</li>
          <li><strong>Arizona ROC:</strong> ${escapeHtml(settings.roc_numbers)}</li>
          <li><strong>Insurance:</strong> ${escapeHtml(settings.insurance_statement)}</li>
          <li><strong>Closeout discipline:</strong> Written change approvals and verified completion reviews—without unverified speed guarantees.</li>
        </ul>
        <p style="margin-bottom:0;"><a href="/credentials/">View credentials &amp; download Capabilities PDF</a></p>
      </div>
    </div>
  </section>

  <!-- 10. Final Inquiry -->
  <section class="section section--carbon" aria-labelledby="final-cta-title">
    <div class="container">
      <span class="eyebrow" style="color:#D4CEC2;">Start a Conversation</span>
      <h2 id="final-cta-title">Tell us about your Greater Phoenix property</h2>
      <p>Share the property city or ZIP, what needs attention, and how you prefer to be reached. Photographs or an RFP PDF are optional—a request starts a conversation, with no automated estimate or minimum project size.</p>
      <div class="hero__actions">
        <a href="/request-proposal/" class="btn btn--primary">Request a proposal</a>
        <a href="tel:${escapeHtml(settings.phone_e164)}" class="btn btn--ghost-light" data-track="phone_click">Call ${escapeHtml(settings.phone_display)}</a>
      </div>
    </div>
  </section>
  `;
}

export function renderServiceOverviewPage({ buildingEngineerLive }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Services', href: '/services/' }])}
      <span class="eyebrow">Service Architecture</span>
      <h1>Commercial property services across Greater Phoenix</h1>
      <p style="font-size:1.12rem;color:var(--color-muted-stone);">Organized by buyer need across three core pillars and specialist property paths. Every page clearly distinguishes self-performed work from coordinated specialty trades.</p>

      <div class="grid-3" style="margin-top:2rem;">
        <article class="panel">
          <span class="eyebrow">Pillar 01</span>
          <h2>Recurring property care</h2>
          <p>Scheduled upkeep that keeps retail centers, business parks, and commercial sites presentable.</p>
          <ul>
            <li><a href="/services/day-porter/">Day porter services</a></li>
            <li><a href="/services/recurring-property-care/">Recurring property care</a> (pressure washing, sweeping, roof cleaning/observations)</li>
            ${buildingEngineerLive ? '<li><a href="/services/building-engineer/">Building engineer services</a> (scheduled operations support)</li>' : ''}
          </ul>
        </article>

        <article class="panel">
          <span class="eyebrow">Pillar 02</span>
          <h2>Commercial maintenance &amp; repairs</h2>
          <p>Responsive, accountable scoping for single repairs, multi-task lists, and active industrial sites.</p>
          <ul>
            <li><a href="/services/commercial-maintenance/">Commercial maintenance &amp; repairs</a></li>
            <li><a href="/services/warehouse-repairs/">Warehouse &amp; industrial repairs</a> (scrim, insulation, docks, bollards)</li>
            <li><a href="/services/exterior-site-maintenance/">Exterior &amp; site maintenance</a> (stucco, concrete, gates, drainage)</li>
          </ul>
        </article>

        <article class="panel">
          <span class="eyebrow">Pillar 03</span>
          <h2>Tenant improvements &amp; make-ready</h2>
          <p>Commercial interior alterations, lease-return restoration, and coordinated suite build-outs.</p>
          <ul>
            <li><a href="/services/tenant-improvements/">Tenant improvements &amp; renovations</a></li>
            <li><a href="/services/tenant-move-outs/">Tenant move-outs &amp; make-ready</a></li>
          </ul>
        </article>
      </div>

      <div class="panel panel--light" style="margin-top:2rem;">
        <h2>Need help choosing the right scope?</h2>
        <p>Already an active client needing maintenance routing? Use our <a href="/request-service/">Existing customer service request</a>. Otherwise, start a new inquiry and our team will route your property to the right owner.</p>
        <a href="/request-proposal/" class="btn btn--primary">Request a proposal</a>
      </div>
    </div>
  </section>`;
}

export function renderServiceDetailPage({ page, rev, contextualCampaign, relatedProjects, settings }) {
  let scopes = [];
  let faqs = [];
  try { scopes = JSON.parse(rev.scopes_json || '[]'); } catch { scopes = []; }
  try { faqs = JSON.parse(rev.faqs_json || '[]'); } catch { faqs = []; }

  return `
  <section class="hero" data-service-id="${escapeHtml(page.service_family || page.slug)}">
    <div class="container">
      ${renderBreadcrumbs([
        { label: 'Home', href: '/' },
        { label: 'Services', href: '/services/' },
        { label: rev.title, href: page.slug },
      ])}
      <div class="hero__grid">
        <div>
          <span class="eyebrow">Greater Phoenix Commercial Service</span>
          <h1>${escapeHtml(rev.hero_headline)}</h1>
          <p style="font-size:1.12rem;color:var(--color-muted-stone);">${escapeHtml(rev.hero_summary)}</p>
          <div class="hero__actions">
            <a href="${escapeHtml(rev.cta_route)}" class="btn btn--primary">${escapeHtml(rev.cta_label)}</a>
            <a href="tel:${escapeHtml(settings.phone_e164)}" class="btn btn--secondary" data-track="phone_click">Call ${escapeHtml(settings.phone_display)}</a>
          </div>
        </div>
        <div class="hero__media">
          <img src="/assets/hero-architecture.svg" alt="${escapeHtml(rev.title)} scope illustration" width="640" height="460" fetchpriority="high">
        </div>
      </div>
    </div>
  </section>

  ${
    contextualCampaign
      ? `<section class="section" style="padding-bottom:0;" aria-label="Featured seasonal note">
          <div class="container">
            <div class="seasonal-feature" data-campaign-id="${escapeHtml(contextualCampaign.campaign_id)}" data-placement-id="service_contextual" data-revision="${escapeHtml(contextualCampaign.content_revision)}">
              <div>
                <span class="eyebrow">Seasonal Highlight</span>
                <h2>${escapeHtml(contextualCampaign.heading)}</h2>
                <p>${escapeHtml(contextualCampaign.summary)}</p>
                <a href="${escapeHtml(contextualCampaign.cta_destination)}" class="btn btn--primary" data-campaign-cta="service_contextual">${escapeHtml(contextualCampaign.cta_label)}</a>
              </div>
            </div>
          </div>
        </section>`
      : ''
  }

  <section class="section">
    <div class="container">
      <div class="grid-2" style="align-items:start;">
        <div>
          ${sanitizeRichHtml(rev.body_html)}
        </div>
        <aside class="panel">
          <span class="eyebrow">Representative Scopes &amp; Boundaries</span>
          <h2>What this service covers</h2>
          ${
            scopes.length > 0
              ? `<ul style="padding-inline-start:1.2rem;">
                  ${scopes.map((s) => `<li style="margin-bottom:0.75rem;"><strong>${escapeHtml(s.name)}:</strong> ${escapeHtml(s.detail)}</li>`).join('')}
                </ul>`
              : '<p>Scopes are confirmed in writing based on site access, operating hours, and specialty trade requirements.</p>'
          }
          <hr style="border:none;border-top:1px solid rgba(36,37,31,0.18);margin:1.25rem 0;">
          <p style="font-size:0.9rem;"><strong>Availability:</strong> Greater Phoenix metro area (local and out-of-state property managers supported).</p>
          <p style="font-size:0.9rem;margin-bottom:0;"><strong>Delivery model:</strong> In-house personnel paired with coordinated licensed specialists where required.</p>
        </aside>
      </div>
    </div>
  </section>

  ${
    relatedProjects.length > 0
      ? `<section class="section section--bone">
          <div class="container">
            <span class="eyebrow">Related Completed Work</span>
            <h2>Approved projects for this service</h2>
            <div class="grid-3">
              ${relatedProjects
                .map(
                  (p) => `<article class="panel panel--light">
                    <span class="eyebrow">${escapeHtml(p.property_type)} &middot; ${escapeHtml(p.city_region)}</span>
                    <h3><a href="/projects/${escapeHtml(p.slug)}/">${escapeHtml(p.title)}</a></h3>
                    <p>${escapeHtml(p.agreed_scope)}</p>
                  </article>`
                )
                .join('')}
            </div>
          </div>
        </section>`
      : ''
  }

  ${
    faqs.length > 0
      ? `<section class="section ${relatedProjects.length === 0 ? 'section--bone' : ''}" aria-labelledby="faq-heading">
          <div class="container">
            <h2 id="faq-heading">Frequently asked questions</h2>
            <div class="faq-list">
              ${faqs
                .map(
                  (f) => `<details class="faq-item">
                    <summary>${escapeHtml(f.q)}</summary>
                    <div class="faq-item__body"><p>${escapeHtml(f.a)}</p></div>
                  </details>`
                )
                .join('')}
            </div>
          </div>
        </section>`
      : ''
  }

  <section class="section section--carbon">
    <div class="container">
      <h2>Ready to review your property scope?</h2>
      <p>Tell us where the property is located and what needs attention. No automated estimates—just a clear review with our operations team.</p>
      <div class="hero__actions">
        <a href="${escapeHtml(rev.cta_route)}" class="btn btn--primary">${escapeHtml(rev.cta_label)}</a>
        <a href="/services/" class="btn btn--ghost-light">Explore all services</a>
      </div>
    </div>
  </section>`;
}

export function renderPropertyPage({ page, rev }) {
  let scopes = [];
  try { scopes = JSON.parse(rev.scopes_json || '[]'); } catch { scopes = []; }

  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([
        { label: 'Home', href: '/' },
        { label: 'Properties we serve', href: '/properties/' },
        { label: rev.title, href: page.slug },
      ])}
      <span class="eyebrow">Operating Environment</span>
      <h1>${escapeHtml(rev.hero_headline)}</h1>
      <p style="font-size:1.12rem;color:var(--color-muted-stone);">${escapeHtml(rev.hero_summary)}</p>

      <div class="grid-2" style="margin-top:2rem;align-items:start;">
        <div>
          ${sanitizeRichHtml(rev.body_html)}
          <div class="hero__actions">
            <a href="${escapeHtml(rev.cta_route)}" class="btn btn--primary">${escapeHtml(rev.cta_label)}</a>
            <a href="/properties/" class="btn btn--secondary">All property types</a>
          </div>
        </div>
        <div class="panel">
          <h2>Key property considerations</h2>
          ${
            scopes.length > 0
              ? `<ul>${scopes.map((s) => `<li style="margin-bottom:0.7rem;"><strong>${escapeHtml(s.name)}:</strong> ${escapeHtml(s.detail)}</li>`).join('')}</ul>`
              : `<ul class="footer-links" style="color:var(--color-carbon);">
                  <li><a href="/properties/industrial-warehouses/">Industrial &amp; warehouse facilities</a></li>
                  <li><a href="/properties/retail-centers/">Retail centers</a></li>
                  <li><a href="/properties/commercial-offices/">Commercial offices &amp; multi-tenant suites</a></li>
                  <li><a href="/property-managers/">Commercial property management portfolios</a></li>
                </ul>`
          }
        </div>
      </div>
    </div>
  </section>`;
}

export function renderProjectsArchivePage({ projects, filterService, filterProperty, availableServices, availableProperties }) {
  const hasFilters = availableServices.length > 0 || availableProperties.length > 0;
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Projects', href: '/projects/' }])}
      <span class="eyebrow">Completed Work Archive</span>
      <h1>Completed commercial projects</h1>
      <p style="font-size:1.1rem;color:var(--color-muted-stone);">Only verified completed projects with approved naming and media rights are published here.</p>

      ${
        hasFilters && projects.length > 0
          ? `<search style="margin-block:1.5rem;display:block;">
              <form method="GET" action="/projects/" style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:flex-end;">
                <div class="field" style="margin:0;min-width:13rem;">
                  <label for="filter-service">Filter by service</label>
                  <select id="filter-service" name="service">
                    <option value="">All services</option>
                    ${availableServices.map((s) => `<option value="${escapeHtml(s)}"${filterService === s ? ' selected' : ''}>${escapeHtml(s)}</option>`).join('')}
                  </select>
                </div>
                <div class="field" style="margin:0;min-width:13rem;">
                  <label for="filter-property">Filter by property type</label>
                  <select id="filter-property" name="property">
                    <option value="">All property types</option>
                    ${availableProperties.map((p) => `<option value="${escapeHtml(p)}"${filterProperty === p ? ' selected' : ''}>${escapeHtml(p)}</option>`).join('')}
                  </select>
                </div>
                <button type="submit" class="btn btn--secondary">Apply filters</button>
                ${filterService || filterProperty ? '<a href="/projects/" class="btn btn--secondary">Clear filters</a>' : ''}
              </form>
            </search>`
          : ''
      }

      ${
        projects.length === 0
          ? `<div class="panel" style="margin-top:2rem;">
              <h2>Approved project case studies are being prepared</h2>
              <p>Service Maintenance publishes completed projects only after work is documented, client naming permissions are recorded, and photography rights are verified. Rather than displaying fabricated examples or placeholder stock images, this archive stays empty until approved work is ready.</p>
              <div class="hero__actions">
                <a href="/services/" class="btn btn--secondary">Explore our services</a>
                <a href="/request-proposal/" class="btn btn--primary">Discuss your property project</a>
              </div>
            </div>`
          : `<div class="grid-3" style="margin-top:1.75rem;">
              ${projects
                .map(
                  (p) => `<article class="panel">
                    ${
                      p.cover_derivative_key
                        ? renderResponsivePicture({
                            src: `/media/${p.cover_derivative_key}`,
                            variantsJson: p.cover_variants_json,
                            alt: p.cover_alt || p.title,
                            width: 400,
                            height: 300,
                            focalX: p.cover_focal_x ?? 50,
                            focalY: p.cover_focal_y ?? 50,
                            style: 'margin-bottom:1rem;aspect-ratio:4/3;',
                          })
                        : ''
                    }
                    <span class="eyebrow">${escapeHtml(p.property_type)} &middot; ${escapeHtml(p.city_region)}</span>
                    <h2><a href="/projects/${escapeHtml(p.slug)}/">${escapeHtml(p.title)}</a></h2>
                    <p style="font-size:0.94rem;">${escapeHtml(p.agreed_scope)}</p>
                    <p class="muted" style="font-size:0.85rem;margin-bottom:0;">Completed: ${escapeHtml(p.completion_date || 'Documented')}</p>
                  </article>`
                )
                .join('')}
            </div>`
      }
    </div>
  </section>`;
}

export function renderProjectDetailPage({ project, pairs, gallery, isPreview = false }) {
  let related = [];
  try { related = JSON.parse(project.related_services_json || '[]'); } catch { related = []; }

  return `
  <section class="section" data-project-id="${escapeHtml(project.project_id)}">
    <div class="container">
      ${renderBreadcrumbs([
        { label: 'Home', href: '/' },
        { label: 'Projects', href: '/projects/' },
        { label: project.title, href: `/projects/${project.slug}/` },
      ])}
      <span class="eyebrow">${escapeHtml(project.property_type)} &middot; ${escapeHtml(project.city_region)} &middot; Completed ${escapeHtml(project.completion_date || 'Verified')}</span>
      <h1>${escapeHtml(project.title)}</h1>
      <p class="muted">${project.naming_decision === 'named' && project.client_name_internal ? `Client: ${escapeHtml(project.client_name_internal)}` : 'Client identity anonymized per project disclosure settings.'}</p>

      <div class="grid-2" style="margin-top:1.75rem;">
        <div class="panel">
          <h2>Scope &amp; Delivery</h2>
          <p><strong>Challenge:</strong> ${escapeHtml(project.challenge)}</p>
          <p><strong>Agreed Scope:</strong> ${escapeHtml(project.agreed_scope)}</p>
          <p><strong>Delivery Role:</strong> ${escapeHtml(project.delivery_role)}</p>
          <p><strong>Self-Performed Elements:</strong> ${escapeHtml(project.self_performed_notes)}</p>
          <p><strong>Coordinated Specialists:</strong> ${escapeHtml(project.coordinated_notes)}</p>
        </div>
        <div class="panel panel--light">
          <h2>Execution &amp; Verified Outcome</h2>
          <p><strong>Operating Constraints:</strong> ${escapeHtml(project.operating_constraints)}</p>
          <p><strong>Completed Work:</strong> ${escapeHtml(project.completed_work)}</p>
          <p><strong>Verified Result:</strong> ${escapeHtml(project.verified_result)}</p>
          ${
            related.length > 0
              ? `<p><strong>Related Services:</strong> ${related
                  .map((s) => `<a href="/services/${escapeHtml(s)}/">${escapeHtml(s)}</a>`)
                  .join(', ')}</p>`
              : ''
          }
          <a href="/request-proposal/" class="btn btn--primary" style="margin-top:0.5rem;">Discuss a similar scope</a>
        </div>
      </div>

      ${
        pairs.length > 0
          ? `<section style="margin-top:2.5rem;" aria-labelledby="ba-heading">
              <h2 id="ba-heading">Before &amp; After Documentation</h2>
              <p class="muted">Labeled static comparisons are shown side-by-side on wider screens and stacked Before then After on mobile.</p>
              ${pairs.map((pair, idx) => renderBeforeAfterPair(pair, idx, isPreview)).join('')}
            </section>`
          : ''
      }

      ${
        gallery.length > 0
          ? `<section style="margin-top:2.5rem;" aria-labelledby="gallery-heading">
              <h2 id="gallery-heading">Project Gallery</h2>
              <div class="grid-3">
                ${gallery
                  .map((g) => {
                    const src = isPreview ? `/admin/api/media/preview/${g.asset_id}` : `/media/${g.public_derivative_key}`;
                    return `<figure class="ba-figure">
                      ${renderResponsivePicture({
                        src,
                        variantsJson: isPreview ? null : g.variants_json,
                        alt: g.alt_text || project.title,
                        width: g.width || 800,
                        height: g.height || 600,
                        focalX: g.focal_x ?? 50,
                        focalY: g.focal_y ?? 50,
                      })}
                      ${g.caption ? `<figcaption>${escapeHtml(g.caption)}</figcaption>` : ''}
                    </figure>`;
                  })
                  .join('')}
              </div>
            </section>`
          : ''
      }
    </div>
  </section>`;
}

export function renderAboutPage({ settings }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'About', href: '/about/' }])}
      <span class="eyebrow">Company Story &amp; Values</span>
      <h1>Our roots date to 1989 across Greater Phoenix</h1>
      <p style="font-size:1.12rem;color:var(--color-muted-stone);">Service Maintenance is the trading name of <strong>${escapeHtml(settings.legal_entity)}</strong>, delivering recurring property care, commercial repairs, and tenant improvements.</p>

      <h2 style="margin-top:2rem;">Company Milestones</h2>
      <table class="data-table">
        <caption>Historical development of Service Maintenance and Promptitude Inc.</caption>
        <thead>
          <tr><th scope="col">Year</th><th scope="col">Milestone</th></tr>
        </thead>
        <tbody>
          <tr><th scope="row">1989</th><td>Patrick Voita founded Service Maintenance, initially providing commercial day porter services.</td></tr>
          <tr><th scope="row">1992</th><td>The original Service Maintenance Inc. was incorporated.</td></tr>
          <tr><th scope="row">2006</th><td>Greg Vandenberg joined as co-owner and general manager and helped expand commercial tenant improvement work.</td></tr>
          <tr><th scope="row">2020</th><td>Promptitude Inc. acquired the business on June 29 and expanded larger tenant improvement capabilities while maintaining recurring care and repairs.</td></tr>
          <tr><th scope="row">Present</th><td>Serving commercial property owners, managers, and facilities teams across Greater Phoenix through in-house teams and coordinated specialty trades.</td></tr>
        </tbody>
      </table>

      <div class="grid-2" style="margin-top:2rem;">
        <div class="panel">
          <h2>Our Approach &amp; Operating Commitments</h2>
          <p><em><!-- CLIENT APPROVAL REQUIRED: Final mission and vision wording is pending client review. The statements below reflect the operational approach currently in use and should be confirmed before publication. --></em></p>
          <p>Service Maintenance helps commercial owners and property teams maintain well-cared-for properties through dependable service, clear communication, and carefully managed work.</p>
          <p style="margin-bottom:0;">Our team builds lasting relationships across Greater Phoenix as the commercial property partner clients turn to for ongoing care and improvement.</p>
        </div>
        <div class="panel panel--light">
          <h2>Five Core Values in Practice</h2>
          <ul>
            <li><strong>Integrity:</strong> Explain scope, pricing boundaries, and subcontractor roles honestly.</li>
            <li><strong>Accountability:</strong> Own commitments and follow-through from assessment through closeout.</li>
            <li><strong>Customer Commitment:</strong> Understand the property’s operating hours, tenants, and constraints.</li>
            <li><strong>Quality and Safety:</strong> Work carefully with attention to site protection and PPE.</li>
            <li><strong>Teamwork &amp; Continuous Improvement:</strong> Share knowledge and refine how work is coordinated.</li>
          </ul>
        </div>
      </div>
    </div>
  </section>`;
}

export function renderCredentialsPage({ settings }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Credentials', href: '/credentials/' }])}
      <span class="eyebrow">Procurement &amp; Vendor Onboarding</span>
      <h1>Credentials, licensing &amp; Capabilities Statement</h1>
      <p style="font-size:1.1rem;color:var(--color-muted-stone);">Verify legal entity details, Arizona Registrar of Contractors numbers, insurance confirmation process, and download our ungated Capabilities Statement.</p>

      <div class="grid-2" style="margin-top:1.75rem;">
        <div class="panel">
          <h2>Legal Identity &amp; Licensing</h2>
          <dl>
            <dt><strong>Trading Name</strong></dt><dd style="margin-bottom:0.6rem;">${escapeHtml(settings.trading_name)}</dd>
            <dt><strong>Legal Entity</strong></dt><dd style="margin-bottom:0.6rem;">${escapeHtml(settings.legal_entity)}</dd>
            <dt><strong>Arizona ROC Numbers</strong></dt>
            <dd style="margin-bottom:0.6rem;">${escapeHtml(settings.roc_numbers)}<br><small class="muted">Verify current active status and classifications via <a href="https://roc.az.gov/" target="_blank" rel="noopener noreferrer">roc.az.gov</a>. License numbers do not imply all trades are self-performed in-house.</small></dd>
            <dt><strong>Insurance Documentation</strong></dt><dd style="margin-bottom:0.6rem;">${escapeHtml(settings.insurance_statement)}</dd>
            <dt><strong>Office Telephone &amp; Hours</strong></dt><dd>${escapeHtml(settings.phone_display)} &middot; ${escapeHtml(settings.hours_display)}</dd>
          </dl>
        </div>

        <div class="panel panel--light">
          <h2>Capabilities Statement (PDF &amp; HTML)</h2>
          <p>Download our concise procurement overview without filling out a contact form. Certificates of Insurance (COIs) and vendor onboarding packages are provided via our monitored operations workflow.</p>
          <div class="hero__actions">
            <a href="/credentials/capabilities.pdf" class="btn btn--primary" download="Service-Maintenance-Capabilities.pdf" data-track="download_capabilities">Download Capabilities PDF</a>
            <a href="/request-proposal/?service=procurement" class="btn btn--secondary">Request Insurance / Onboarding Docs</a>
          </div>
          <p class="muted" style="font-size:0.86rem;margin-top:1rem;margin-bottom:0;">Note: Downloading the Capabilities PDF is ungated and is not treated as a qualified sales lead.</p>
        </div>
      </div>

      <section style="margin-top:2.5rem;" aria-labelledby="html-cap-title">
        <h2 id="html-cap-title">Accessible HTML Capabilities Summary</h2>
        <p><strong>Service Pillars:</strong> (1) Recurring Property Care (day porter, pressure washing, sweeping, roof cleaning/observations); (2) Commercial Maintenance &amp; Repairs (interior finishes, doors/hardware, electrical/plumbing coordination, concrete, warehouse scrim/insulation, welding); (3) Tenant Improvements &amp; Make-Ready (interior build-outs, white-shell turnovers, final cleaning).</p>
        <p><strong>Primary Property Types:</strong> Industrial, warehouse, and distribution facilities; retail centers; commercial office and multi-tenant buildings; commercial property management portfolios.</p>
        <p><strong>Geographic Coverage:</strong> Greater Phoenix, Arizona.</p>
      </section>
    </div>
  </section>`;
}

export function renderServiceAreaPage({ settings }) {
  let cities = [];
  try { cities = JSON.parse(settings.service_area_cities_json || '[]'); } catch { cities = []; }
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Service Area', href: '/service-area/' }])}
      <span class="eyebrow">Geography</span>
      <h1>Greater Phoenix commercial service area</h1>
      <p style="font-size:1.1rem;color:var(--color-muted-stone);">Dispatch and project coordination across the Greater Phoenix metropolitan corridor. Out-of-state owners and national property managers overseeing Phoenix-area assets are welcome—eligibility is based on where the property is located.</p>

      <div class="panel" style="margin-top:1.75rem;">
        <h2>Markets Reviewed for Dispatch Coverage</h2>
        <p>Candidate Greater Phoenix coverage areas include (subject to specific scope and schedule capacity):</p>
        <ul style="columns:2;max-width:34rem;">
          ${cities.map((c) => `<li>${escapeHtml(c)}, AZ</li>`).join('')}
        </ul>
        <p class="muted" style="font-size:0.9rem;margin-bottom:0;">Service Maintenance operates from our Tempe base (${escapeHtml(settings.address_display)}) and does not operate fake branch offices in surrounding cities.</p>
      </div>
      <div class="hero__actions">
        <a href="/request-proposal/" class="btn btn--primary">Confirm coverage for your property</a>
      </div>
    </div>
  </section>`;
}

export function renderContactPage({ settings }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Contact', href: '/contact/' }])}
      <span class="eyebrow">Monitored Company Contacts</span>
      <h1>Contact Service Maintenance</h1>
      <div class="grid-3" style="margin-top:1.75rem;">
        <article class="panel">
          <h2>New Proposals &amp; Assessments</h2>
          <p>Request a scope review for day porter programs, building repairs, warehouse work, or tenant improvements.</p>
          <a href="/request-proposal/" class="btn btn--primary">Request a proposal</a>
        </article>
        <article class="panel">
          <h2>Existing Client Service</h2>
          <p>Active clients needing maintenance routing can submit directly to our operations queue.</p>
          <a href="/request-service/" class="btn btn--secondary">Request service</a>
        </article>
        <article class="panel">
          <h2>Careers &amp; Subcontractors</h2>
          <p>Job seekers apply via <a href="/careers/">Current Openings</a>. Specialty subcontractors or vendors may reach our monitored office inbox.</p>
          <a href="mailto:${escapeHtml(settings.monitored_inbox)}" class="btn btn--secondary" data-track="email_click">Email ${escapeHtml(settings.monitored_inbox)}</a>
        </article>
      </div>
      <div class="panel panel--light" style="margin-top:2rem;">
        <h2>Office Details (${escapeHtml(settings.timezone)})</h2>
        <p><strong>Telephone:</strong> <a href="tel:${escapeHtml(settings.phone_e164)}" data-track="phone_click">${escapeHtml(settings.phone_display)}</a><br>
        <strong>Hours:</strong> ${escapeHtml(settings.hours_display)}<br>
        <strong>Address Reference:</strong> ${escapeHtml(settings.address_display)}<br>
        <strong>Legal Entity:</strong> ${escapeHtml(settings.legal_entity)} (${escapeHtml(settings.roc_numbers)})</p>
      </div>
    </div>
  </section>`;
}

export function renderProposalFormPage({ preselectedService = '', settings, csrfToken }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Request a proposal', href: '/request-proposal/' }])}
      <span class="eyebrow">New Commercial Inquiry</span>
      <h1>Request a proposal or property assessment</h1>
      <p style="font-size:1.05rem;color:var(--color-muted-stone);">Provide your contact details, where the commercial property is located, and a brief note on what needs attention. No automated estimate or minimum project size is implied.</p>

      <div id="form-error-summary" class="error-summary" hidden tabindex="-1" role="alert">
        <h2>Please review the highlighted fields</h2>
        <ul id="form-error-list"></ul>
      </div>

      <div id="form-server-failure" class="status-banner status-banner--error" hidden role="alert">
        <strong>Submission was not confirmed.</strong> Your entries have been preserved below so you can retry safely or call us directly at
        <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)}).
      </div>

      <form id="proposal-form" class="form-stack" method="POST" action="/api/inquiries" enctype="multipart/form-data" novalidate data-form-type="proposal">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="idempotency_key" id="idempotency_key" value="">
        <input type="hidden" name="privacy_notice_version" value="${escapeHtml(PRIVACY_NOTICE_VERSION)}">
        <!-- Accessible honeypot for abuse control -->
        <div class="visually-hidden" aria-hidden="true">
          <label for="website_url_hp">Leave blank</label>
          <input type="text" id="website_url_hp" name="website_url_hp" tabindex="-1" autocomplete="off">
        </div>

        <div class="field">
          <label for="name">Your name <span aria-hidden="true">*</span></label>
          <input type="text" id="name" name="name" required maxlength="100" autocomplete="name" data-error="err-name">
          <div id="err-name" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your name (up to 100 characters).</div>
        </div>

        <div class="field">
          <label for="company">Company or organization <span aria-hidden="true">*</span></label>
          <span id="hint-company" class="hint">Commercial property firm, owner, or tenant business name.</span>
          <input type="text" id="company" name="company" required maxlength="150" autocomplete="organization" aria-describedby="hint-company" data-error="err-company">
          <div id="err-company" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your company or organization name.</div>
        </div>

        <fieldset class="choice-group">
          <legend>Preferred contact method <span aria-hidden="true">*</span></legend>
          <div class="choice-row">
            <input type="radio" id="pref-email" name="preferred_contact_method" value="email" checked>
            <label for="pref-email">Email</label>
          </div>
          <div class="choice-row">
            <input type="radio" id="pref-phone" name="preferred_contact_method" value="telephone">
            <label for="pref-phone">Telephone</label>
          </div>
        </fieldset>

        <div class="field">
          <label for="email">Email address <span id="email-req-mark" aria-hidden="true">*</span></label>
          <span id="hint-email" class="hint">Personal or business email domains are both accepted.</span>
          <input type="email" id="email" name="email" autocomplete="email" inputmode="email" autocorrect="off" autocapitalize="none" spellcheck="false" aria-describedby="hint-email" data-error="err-email" required>
          <div id="err-email" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid email address (for example, name@company.com).</div>
        </div>

        <div class="field">
          <label for="telephone">Telephone <span id="phone-req-mark" class="visually-hidden">(optional when email selected)</span></label>
          <span id="hint-phone" class="hint">US or international phone formats supported for remote property owners.</span>
          <input type="tel" id="telephone" name="telephone" autocomplete="tel" inputmode="tel" aria-describedby="hint-phone" data-error="err-telephone">
          <div id="err-telephone" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid telephone number (7 to 15 digits).</div>
        </div>

        <div class="field">
          <label for="service_needed">Service needed <span aria-hidden="true">*</span></label>
          <select id="service_needed" name="service_needed" required data-error="err-service">
            <option value="">Select a service...</option>
            ${SERVICE_FAMILIES.filter((s) => !s.conditional)
              .map(
                (s) =>
                  `<option value="${escapeHtml(s.id)}"${preselectedService === s.id ? ' selected' : ''}>${escapeHtml(s.label)}</option>`
              )
              .join('')}
          </select>
          <div id="err-service" class="error-msg"><span role="img" aria-label="Error">!</span> Select the service needed.</div>
        </div>

        <div class="field">
          <label for="property_city_or_zip">Property city or ZIP <span aria-hidden="true">*</span></label>
          <span id="hint-prop-loc" class="hint">Location of the commercial property (even if your office is outside Arizona).</span>
          <input type="text" id="property_city_or_zip" name="property_city_or_zip" required maxlength="120" aria-describedby="hint-prop-loc" data-error="err-prop-loc">
          <div id="err-prop-loc" class="error-msg"><span role="img" aria-label="Error">!</span> Enter the property city or ZIP.</div>
        </div>

        <div class="field">
          <label for="property_type">Property type (optional)</label>
          <select id="property_type" name="property_type">
            <option value="">Prefer not to specify / Not sure</option>
            <option value="warehouse-industrial">Warehouse / Industrial / Distribution</option>
            <option value="retail">Retail Center</option>
            <option value="office">Office / Multi-Tenant Commercial</option>
            <option value="other-commercial">Other Commercial</option>
          </select>
        </div>

        <div class="field">
          <label for="desired_timing">Desired timing (optional)</label>
          <select id="desired_timing" name="desired_timing">
            <option value="flexible">Flexible / Exploratory</option>
            <option value="planning">Planning ahead</option>
            <option value="upcoming">Upcoming work (next 30–60 days)</option>
            <option value="time-sensitive">Time-sensitive need</option>
            <option value="date-range">Specific date window</option>
          </select>
        </div>

        <div id="time-sensitive-note" class="status-banner status-banner--warning" hidden>
          <strong>Time-sensitive inquiry note:</strong> Our monitored office line is <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)}). Submitting this form routes your request for operational review; it does not imply immediate dispatch.
        </div>

        <div class="choice-row" style="margin-bottom:1.25rem;">
          <input type="checkbox" id="multiple_properties" name="multiple_properties">
          <label for="multiple_properties">This inquiry covers multiple commercial properties</label>
        </div>

        <div id="multi-prop-fields" class="panel" hidden style="margin-bottom:1.4rem;">
          <div class="field">
            <label for="site_count">Approximate number of sites</label>
            <input type="text" id="site_count" name="site_count" maxlength="40">
          </div>
          <div class="field" style="margin-bottom:0;">
            <label for="coverage_detail">Cities / portfolio overview</label>
            <input type="text" id="coverage_detail" name="coverage_detail" maxlength="300">
          </div>
        </div>

        <!-- Conditional TI/RFP Section -->
        <div id="ti-conditional-fields" class="panel" hidden style="margin-bottom:1.4rem;">
          <h3>Tenant Improvement / RFP Details (Optional)</h3>
          <div class="field"><label for="ti_property_address">Property street address</label><input type="text" id="ti_property_address" name="ti_property_address" maxlength="200"></div>
          <div class="field"><label for="ti_occupancy">Space condition</label>
            <select id="ti_occupancy" name="ti_occupancy"><option value="">Select...</option><option value="occupied">Occupied</option><option value="vacant">Vacant</option><option value="partial">Partially occupied</option></select>
          </div>
          <div class="field"><label for="ti_plans_available">Architectural plans / drawings status</label>
            <select id="ti_plans_available" name="ti_plans_available">
              <option value="">Select...</option>
              <option value="Complete plans available">Complete plans available</option>
              <option value="Preliminary sketches only">Preliminary sketches only</option>
              <option value="No plans yet — scope estimate needed">No plans yet — scope estimate needed</option>
            </select>
          </div>
          <div class="field"><label for="ti_bid_due_date">Bid due date (if RFP)</label><input type="date" id="ti_bid_due_date" name="ti_bid_due_date"></div>
          <div class="field"><label for="ti_completion_window">Target completion window</label><input type="text" id="ti_completion_window" name="ti_completion_window" maxlength="80"></div>
          <div class="field"><label for="project_budget">Estimated project budget band</label>
            <select id="project_budget" name="project_budget">
              <option value="Not established">Not established</option>
              <option value="Prefer to discuss">Prefer to discuss</option>
              <option value="Under $25,000">Under $25,000</option>
              <option value="$25,000 - $100,000">$25,000 - $100,000</option>
              <option value="Over $100,000">Over $100,000</option>
            </select>
          </div>
          <div class="field" style="margin-bottom:0;"><label for="ti_landlord_involvement">Owner / landlord approval contact</label><input type="text" id="ti_landlord_involvement" name="ti_landlord_involvement" maxlength="120"></div>
        </div>

        <!-- Conditional Recurring Care Section -->
        <div id="recurring-conditional-fields" class="panel" hidden style="margin-bottom:1.4rem;">
          <h3>Recurring Program Details (Optional)</h3>
          <div class="field"><label for="rc_frequency">Desired service frequency</label><input type="text" id="rc_frequency" name="rc_frequency" maxlength="60"></div>
          <div class="field"><label for="rc_site_size">Approximate site size / building count</label><input type="text" id="rc_site_size" name="rc_site_size" maxlength="80"></div>
          <div class="field" style="margin-bottom:0;"><label for="rc_current_arrangement">Current service arrangement &amp; main concerns</label><input type="text" id="rc_current_arrangement" name="rc_current_arrangement" maxlength="200"></div>
        </div>

        <div class="field">
          <label for="description">Brief description of what needs attention <span aria-hidden="true">*</span></label>
          <span id="hint-desc" class="hint">Share the work needed, access hours, or questions. Do not include security gate codes or sensitive passwords.</span>
          <textarea id="description" name="description" required maxlength="3000" aria-describedby="hint-desc" data-error="err-desc"></textarea>
          <div id="err-desc" class="error-msg"><span role="img" aria-label="Error">!</span> Describe what needs attention.</div>
        </div>

        <div class="field">
          <label for="attachments">Optional site photos or RFP documents</label>
          <span id="hint-files" class="hint">Allowed: PDF, JPEG, or PNG. Up to 5 files, 10 MB per file, 25 MB total. For HEIC or large drawings, submit without files and our team will send a secure upload link.</span>
          <input type="file" id="attachments" name="attachments" multiple accept=".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png" aria-describedby="hint-files">
          <div id="upload-status" class="hint" aria-live="polite"></div>
        </div>

        <div class="panel panel--light" style="margin-bottom:1.4rem;">
          <p style="font-size:0.9rem;margin-bottom:0.75rem;">
            <strong>Privacy Notice:</strong> Information submitted here is used to review and respond to your commercial service inquiry (<a href="/privacy/">Privacy Policy</a>).
          </p>
          <div class="choice-row">
            <input type="checkbox" id="marketing_opt_in" name="marketing_opt_in">
            <label for="marketing_opt_in">Optional: Send occasional seasonal property care reminders from Service Maintenance (never required to request a proposal).</label>
          </div>
        </div>

        <button type="submit" class="btn btn--primary" id="submit-proposal-btn">Submit proposal request</button>
      </form>
    </div>
  </section>`;
}

export function renderServiceRequestFormPage({ settings, csrfToken }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Existing customer service', href: '/request-service/' }])}
      <span class="eyebrow">Operations Routing</span>
      <h1>Existing customer service request</h1>
      <p style="font-size:1.05rem;color:var(--color-muted-stone);">Submit a maintenance or property care request for an active commercial account. Submitting this form routes your request to operations for review and does not claim an approved work order or guaranteed dispatch time.</p>

      <div id="form-error-summary" class="error-summary" hidden tabindex="-1" role="alert">
        <h2>Please review the highlighted fields</h2>
        <ul id="form-error-list"></ul>
      </div>

      <div id="form-server-failure" class="status-banner status-banner--error" hidden role="alert">
        <strong>Request was not confirmed.</strong> Your entries are preserved below. Call our office line at <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)}).
      </div>

      <form id="service-request-form" class="form-stack" method="POST" action="/api/service-requests" novalidate data-form-type="service_request">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="idempotency_key" id="idempotency_key" value="">

        <div class="field">
          <label for="sr-name">Your name <span aria-hidden="true">*</span></label>
          <input type="text" id="sr-name" name="name" required maxlength="100" autocomplete="name" data-error="err-sr-name">
          <div id="err-sr-name" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your name.</div>
        </div>

        <div class="field">
          <label for="sr-company">Company / Management Firm <span aria-hidden="true">*</span></label>
          <input type="text" id="sr-company" name="company" required maxlength="150" autocomplete="organization" data-error="err-sr-company">
          <div id="err-sr-company" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your company name.</div>
        </div>

        <fieldset class="choice-group">
          <legend>Preferred contact method <span aria-hidden="true">*</span></legend>
          <div class="choice-row">
            <input type="radio" id="sr-pref-email" name="preferred_contact_method" value="email" checked>
            <label for="sr-pref-email">Email</label>
          </div>
          <div class="choice-row">
            <input type="radio" id="sr-pref-phone" name="preferred_contact_method" value="telephone">
            <label for="sr-pref-phone">Telephone</label>
          </div>
        </fieldset>

        <div class="field">
          <label for="sr-email">Email address</label>
          <input type="email" id="sr-email" name="email" autocomplete="email" required data-error="err-sr-email">
          <div id="err-sr-email" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid email address.</div>
        </div>

        <div class="field">
          <label for="sr-phone">Telephone</label>
          <input type="tel" id="sr-phone" name="telephone" autocomplete="tel" data-error="err-sr-phone">
          <div id="err-sr-phone" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid telephone number.</div>
        </div>

        <div class="field">
          <label for="sr-property">Property name or address <span aria-hidden="true">*</span></label>
          <input type="text" id="sr-property" name="property" required maxlength="200" data-error="err-sr-property">
          <div id="err-sr-property" class="error-msg"><span role="img" aria-label="Error">!</span> Identify the property.</div>
        </div>

        <div class="field">
          <label for="sr-urgency">Urgency category <span aria-hidden="true">*</span></label>
          <select id="sr-urgency" name="urgency" required>
            <option value="routine">Routine scheduled attention</option>
            <option value="priority">Priority business-hours review</option>
            <option value="time-sensitive">Time-sensitive issue (call ${escapeHtml(settings.phone_display)} during business hours)</option>
          </select>
        </div>

        <div class="field">
          <label for="sr-ref">Job / PO / Reference number (optional)</label>
          <input type="text" id="sr-ref" name="reference_number" maxlength="80">
        </div>

        <div class="field">
          <label for="sr-desc">Service request description <span aria-hidden="true">*</span></label>
          <textarea id="sr-desc" name="description" required maxlength="3000" data-error="err-sr-desc"></textarea>
          <div id="err-sr-desc" class="error-msg"><span role="img" aria-label="Error">!</span> Describe the service request.</div>
        </div>

        <button type="submit" class="btn btn--primary" id="submit-sr-btn">Send service request</button>
      </form>
    </div>
  </section>`;
}

export function renderThankYouPage({ receiptId = '', kind = 'new_business', settings }) {
  return `
  <section class="section">
    <div class="container">
      <div class="panel" style="max-width:42rem;">
        <span class="eyebrow">Receipt Confirmed</span>
        <h1>Thank you. We have received your request.</h1>
        <p>Our team will review the details and contact you using your preferred method.</p>
        ${
          receiptId
            ? `<p><strong>Reference ID:</strong> <code>${escapeHtml(receiptId)}</code></p>`
            : '<p class="muted">If you visited this confirmation page directly without submitting a form, no new inquiry was recorded.</p>'
        }
        <p class="muted" style="font-size:0.93rem;">
          ${kind === 'existing_service' ? 'Your request has been routed to operations for review. It is not an automatically scheduled work order.' : 'Next step: An operations or estimating owner reviews your scope and follows up during America/Phoenix business hours.'}
        </p>
        <p>Need to add details by phone? Call <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a>.</p>
        <div class="hero__actions">
          <a href="/" class="btn btn--secondary">Return to Home</a>
          <a href="/services/" class="btn btn--secondary">Explore Services</a>
        </div>
      </div>
    </div>
  </section>`;
}

export function renderCareersOverviewPage({ openJobs, settings }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Careers', href: '/careers/' }])}
      <span class="eyebrow">Working at Service Maintenance</span>
      <h1>Careers &amp; current openings</h1>
      <p style="font-size:1.1rem;color:var(--color-muted-stone);">Service Maintenance supports commercial properties across Greater Phoenix through in-house day porters, maintenance technicians, supervisors, and project managers.</p>

      ${
        openJobs.length === 0
          ? `<div class="panel" style="margin-top:2rem;">
              <h2>No current open positions</h2>
              <p>There are no open positions accepting applications on the website today. We do not keep invented postings open or collect unsolicited resumes on closed cycles.</p>
              <p style="margin-bottom:0;">For general employment inquiries, contact our recruiting team at <a href="mailto:${escapeHtml(settings.recruiting_contact)}">${escapeHtml(settings.recruiting_contact)}</a> or call <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a>.</p>
            </div>`
          : `<div class="grid-2" style="margin-top:2rem;">
              ${openJobs
                .map(
                  (j) => `<article class="panel">
                    <span class="eyebrow">${escapeHtml(j.employment_type)} &middot; ${escapeHtml(j.role_family)}</span>
                    <h2><a href="/careers/${escapeHtml(j.slug)}/">${escapeHtml(j.title)}</a></h2>
                    <p><strong>Work Area:</strong> ${escapeHtml(j.work_area)}<br>
                    <strong>Schedule:</strong> ${escapeHtml(j.schedule_text)}</p>
                    <div class="hero__actions">
                      <a href="/careers/${escapeHtml(j.slug)}/" class="btn btn--secondary">View role</a>
                      <a href="/careers/${escapeHtml(j.slug)}/apply/" class="btn btn--primary">Apply now</a>
                    </div>
                  </article>`
                )
                .join('')}
            </div>`
      }
    </div>
  </section>`;
}

export function renderJobDetailPage({ job, settings }) {
  const isOpen = job.status === 'Open';
  const isPaused = job.status === 'Paused';
  return `
  <section class="section" data-job-id="${escapeHtml(job.requisition_id)}" data-job-status="${escapeHtml(job.status)}">
    <div class="container">
      ${renderBreadcrumbs([
        { label: 'Home', href: '/' },
        { label: 'Careers', href: '/careers/' },
        { label: job.title, href: `/careers/${job.slug}/` },
      ])}
      <span class="eyebrow">${escapeHtml(job.employment_type)} &middot; ${escapeHtml(job.role_family)} &middot; Requisition ${escapeHtml(job.requisition_id)}</span>
      <h1>${escapeHtml(job.title)}</h1>

      ${
        !isOpen
          ? `<div class="status-banner status-banner--warning" role="status">
              <strong>${isPaused ? 'Applications temporarily paused' : 'This position is closed'}.</strong>
              ${isPaused ? 'This opening is temporarily paused and not accepting submissions right now.' : 'Applications are no longer being accepted for this position.'}
              <a href="/careers/">View current openings</a> or contact <a href="mailto:${escapeHtml(settings.recruiting_contact)}">${escapeHtml(settings.recruiting_contact)}</a>.
            </div>`
          : ''
      }

      <div class="grid-2" style="margin-top:1.75rem;align-items:start;">
        <div>
          <h2>Responsibilities</h2>
          ${sanitizeRichHtml(job.responsibilities_html)}
          <h2>Qualifications &amp; Experience</h2>
          ${sanitizeRichHtml(job.qualifications_html)}
        </div>
        <aside class="panel">
          <h2>Role Summary</h2>
          <p><strong>Work Area:</strong> ${escapeHtml(job.work_area)}</p>
          <p><strong>Schedule:</strong> ${escapeHtml(job.schedule_text)}</p>
          ${job.travel_requirements ? `<p><strong>Travel / Site Needs:</strong> ${escapeHtml(job.travel_requirements)}</p>` : ''}
          <p><strong>Compensation:</strong> ${escapeHtml(job.pay_info)}</p>
          <p><strong>Benefits:</strong> ${escapeHtml(job.benefits_info)}</p>
          ${
            isOpen
              ? `<a href="/careers/${escapeHtml(job.slug)}/apply/" class="btn btn--primary" style="width:100%;">Apply for this role</a>`
              : `<a href="/careers/" class="btn btn--secondary" style="width:100%;">Back to Careers</a>`
          }
        </aside>
      </div>
    </div>
  </section>`;
}

export function renderJobApplyPage({ job, settings, csrfToken }) {
  if (job.status !== 'Open') {
    return renderJobDetailPage({ job, settings });
  }
  let questions = [];
  try { questions = JSON.parse(job.questions_json || '[]'); } catch { questions = []; }

  return `
  <section class="section" data-job-id="${escapeHtml(job.requisition_id)}">
    <div class="container">
      ${renderBreadcrumbs([
        { label: 'Home', href: '/' },
        { label: 'Careers', href: '/careers/' },
        { label: job.title, href: `/careers/${job.slug}/` },
        { label: 'Apply', href: `/careers/${job.slug}/apply/` },
      ])}
      <span class="eyebrow">Application &middot; ${escapeHtml(job.requisition_id)}</span>
      <h1>Apply for ${escapeHtml(job.title)}</h1>
      <p class="muted">${escapeHtml(job.work_area)} &middot; ${escapeHtml(job.employment_type)}</p>

      <div id="form-error-summary" class="error-summary" hidden tabindex="-1" role="alert">
        <h2>Please review the highlighted fields</h2>
        <ul id="form-error-list"></ul>
      </div>

      <div id="job-closed-banner" class="status-banner status-banner--warning" hidden role="alert">
        <strong>This position has closed while your form was open.</strong> Your entries have been preserved in this browser session, and this submission was not accepted against another role. <a href="/careers/">View current openings</a> or contact <a href="mailto:${escapeHtml(settings.recruiting_contact)}">${escapeHtml(settings.recruiting_contact)}</a>.
      </div>

      <div id="form-server-failure" class="status-banner status-banner--error" hidden role="alert">
        <strong>Application submission was not confirmed.</strong> Please retry or contact recruiting at <a href="mailto:${escapeHtml(settings.recruiting_contact)}">${escapeHtml(settings.recruiting_contact)}</a> / <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a>.
      </div>

      <form id="job-apply-form" class="form-stack" method="POST" action="/api/jobs/${escapeHtml(job.slug)}/apply" enctype="multipart/form-data" novalidate data-form-type="application">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="idempotency_key" id="idempotency_key" value="">
        <input type="hidden" name="requisition_id" value="${escapeHtml(job.requisition_id)}">
        <input type="hidden" name="opening_cycle_id" value="${escapeHtml(job.opening_cycle_id)}">
        <input type="hidden" name="form_revision" value="${escapeHtml(job.form_revision)}">

        <div class="field">
          <label for="app-name">Full name <span aria-hidden="true">*</span></label>
          <input type="text" id="app-name" name="name" required maxlength="100" autocomplete="name" data-error="err-app-name">
          <div id="err-app-name" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your name.</div>
        </div>

        <fieldset class="choice-group">
          <legend>Preferred contact method <span aria-hidden="true">*</span></legend>
          <div class="choice-row">
            <input type="radio" id="app-pref-email" name="preferred_contact_method" value="email" checked>
            <label for="app-pref-email">Email</label>
          </div>
          <div class="choice-row">
            <input type="radio" id="app-pref-phone" name="preferred_contact_method" value="telephone">
            <label for="app-pref-phone">Telephone</label>
          </div>
        </fieldset>

        <div class="field">
          <label for="app-email">Email address</label>
          <input type="email" id="app-email" name="email" autocomplete="email" inputmode="email" required data-error="err-app-email">
          <div id="err-app-email" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid email address.</div>
        </div>

        <div class="field">
          <label for="app-phone">Telephone</label>
          <input type="tel" id="app-phone" name="telephone" autocomplete="tel" inputmode="tel" data-error="err-app-phone">
          <div id="err-app-phone" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid telephone number.</div>
        </div>

        <div class="field">
          <label for="app-city">City or ZIP ${job.require_city_zip ? '<span aria-hidden="true">*</span>' : '(optional)'}</label>
          <span id="hint-app-city" class="hint">Used to review work-area fit; full street address is not required.</span>
          <input type="text" id="app-city" name="city_or_zip" maxlength="80" autocomplete="postal-code" aria-describedby="hint-app-city" ${job.require_city_zip ? 'required' : ''} data-error="err-app-city">
          <div id="err-app-city" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your city or ZIP.</div>
        </div>

        <div class="field">
          <label for="app-exp">Relevant experience ${job.resume_policy === 'required' ? '(or attach resume below)' : '<span aria-hidden="true">*</span>'}</label>
          <span id="hint-app-exp" class="hint">Summarize prior maintenance, porter, trade, or customer-site work (or enter "No prior experience").</span>
          <textarea id="app-exp" name="relevant_experience" maxlength="5000" aria-describedby="hint-app-exp" ${job.resume_policy === 'optional' ? 'required' : ''} data-error="err-app-exp"></textarea>
          <div id="err-app-exp" class="error-msg"><span role="img" aria-label="Error">!</span> Share your relevant experience or attach a resume.</div>
        </div>

        <div class="field">
          <label for="app-avail">Availability / start window (optional)</label>
          <input type="text" id="app-avail" name="availability" maxlength="300">
        </div>

        ${questions
          .map(
            (q) => `<div class="field">
              <label for="q_${escapeHtml(q.id)}">${escapeHtml(q.label)} ${q.required ? '<span aria-hidden="true">*</span>' : ''}</label>
              ${
                q.type === 'select' && Array.isArray(q.options)
                  ? `<select id="q_${escapeHtml(q.id)}" name="q_${escapeHtml(q.id)}" ${q.required ? 'required' : ''} data-error="err-q-${escapeHtml(q.id)}">
                      <option value="">Select...</option>
                      ${q.options.map((opt) => `<option value="${escapeHtml(opt)}">${escapeHtml(opt)}</option>`).join('')}
                    </select>`
                  : `<input type="text" id="q_${escapeHtml(q.id)}" name="q_${escapeHtml(q.id)}" maxlength="1000" ${q.required ? 'required' : ''} data-error="err-q-${escapeHtml(q.id)}">`
              }
              <div id="err-q-${escapeHtml(q.id)}" class="error-msg"><span role="img" aria-label="Error">!</span> Please answer this job question.</div>
            </div>`
          )
          .join('')}

        <div class="field">
          <label for="resume">Resume (${job.resume_policy === 'required' ? 'Required or use alternative contact' : 'Optional'})</label>
          <span id="hint-resume" class="hint">Accepted: one PDF or DOCX file up to 10 MB. Stored securely outside public media libraries.</span>
          <input type="file" id="resume" name="resume" accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" aria-describedby="hint-resume">
          <span class="hint" style="margin-top:0.35rem;">Need help applying or prefer to send your resume another way? Email <a href="mailto:${escapeHtml(settings.recruiting_contact)}">${escapeHtml(settings.recruiting_contact)}</a> or call <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a>.</span>
        </div>

        <div class="panel panel--light" style="margin-bottom:1.4rem;">
          <div class="choice-row">
            <input type="checkbox" id="privacy_ack" name="privacy_ack" required data-error="err-privacy-ack">
            <label for="privacy_ack">I acknowledge that my application information will be stored securely for hiring review by authorized staff (<a href="/privacy/">Privacy Policy</a>). <span aria-hidden="true">*</span></label>
          </div>
          <div id="err-privacy-ack" class="error-msg"><span role="img" aria-label="Error">!</span> Please acknowledge the applicant privacy notice.</div>
        </div>

        <button type="submit" class="btn btn--primary" id="submit-apply-btn">Submit application</button>
      </form>
    </div>
  </section>`;
}

export function renderApplicationReceivedPage({ refId = '', roleTitle = '', attachmentState = '', settings }) {
  return `
  <section class="section">
    <div class="container">
      <div class="panel" style="max-width:42rem;">
        <span class="eyebrow">Application Receipt</span>
        <h1>Application received</h1>
        ${
          refId
            ? `<p>Your application${roleTitle ? ` for <strong>${escapeHtml(roleTitle)}</strong>` : ''} has been recorded in our hiring system.</p>
               <p><strong>Application Reference:</strong> <code>${escapeHtml(refId)}</code></p>`
            : '<p>If you reached this page directly without submitting an application, no new application record was created.</p>'
        }
        ${
          attachmentState === 'quarantined'
            ? '<div class="status-banner status-banner--warning">Note: Your application was saved, but the optional resume attachment could not pass security validation. Hiring reviewers can follow up securely if needed.</div>'
            : ''
        }
        <p class="muted" style="font-size:0.93rem;">Submitting an application confirms receipt only; it does not promise an interview or response deadline. Questions? Contact <a href="mailto:${escapeHtml(settings.recruiting_contact)}">${escapeHtml(settings.recruiting_contact)}</a> or call <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a>.</p>
        <a href="/careers/" class="btn btn--secondary">Back to Careers</a>
      </div>
    </div>
  </section>`;
}

export function renderCampaignLandingPage({ campaign, expired = false }) {
  const hasImg = Boolean(!expired && campaign.asset && campaign.asset.public_derivative_key);
  return `
  <section class="section">
    <div class="container">
      <span class="eyebrow">Seasonal Focus &middot; Greater Phoenix</span>
      ${
        expired
          ? `<div class="status-banner status-banner--warning">
              <strong>This seasonal highlight has ended.</strong> View our active commercial property services below or request a current scope review.
            </div>
            <h1>${escapeHtml(campaign.heading)}</h1>
            <p>This seasonal campaign window has closed. Our core commercial maintenance, day porter, and tenant improvement services remain available year-round.</p>
            <div class="hero__actions">
              <a href="/services/" class="btn btn--primary">Explore our services</a>
              <a href="/request-proposal/" class="btn btn--secondary">Request a proposal</a>
            </div>`
          : `<div class="${hasImg ? 'hero__grid' : ''}">
              <div>
                <h1>${escapeHtml(campaign.heading)}</h1>
                <p style="font-size:1.15rem;color:var(--color-muted-stone);">${escapeHtml(campaign.summary)}</p>
                <div class="hero__actions">
                  <a href="${escapeHtml(campaign.cta_destination)}" class="btn btn--primary">${escapeHtml(campaign.cta_label)}</a>
                  <a href="/services/" class="btn btn--secondary">View all services</a>
                </div>
              </div>
              ${
                hasImg
                  ? `<div class="hero__media">
                      <img src="/media/${escapeHtml(campaign.asset.public_derivative_key)}"
                           alt="${escapeHtml(campaign.asset.alt_text || campaign.heading)}"
                           width="${escapeHtml(campaign.asset.width || 640)}"
                           height="${escapeHtml(campaign.asset.height || 460)}"
                           style="object-fit:cover;object-position:${escapeHtml(campaign.asset.focal_x ?? 50)}% ${escapeHtml(campaign.asset.focal_y ?? 50)}%;border-radius:2px;">
                    </div>`
                  : ''
              }
            </div>`
      }
    </div>
  </section>`;
}

export function renderInsightsArchivePage({ articles }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Insights', href: '/insights/' }])}
      <span class="eyebrow">Operational Guides</span>
      <h1>Insights for commercial property teams</h1>
      ${
        articles.length === 0
          ? '<div class="panel"><p>No published articles are currently available. Visit <a href="/services/">Services</a> for full capability details.</p></div>'
          : `<div class="grid-3" style="margin-top:1.75rem;">
              ${articles
                .map(
                  (a) => `<article class="panel">
                    <span class="eyebrow">${escapeHtml(a.buyer_target)}</span>
                    <h2><a href="/insights/${escapeHtml(a.slug)}/">${escapeHtml(a.title)}</a></h2>
                    <p>${escapeHtml(a.summary)}</p>
                  </article>`
                )
                .join('')}
            </div>`
      }
    </div>
  </section>`;
}

export function renderArticleDetailPage({ article }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([
        { label: 'Home', href: '/' },
        { label: 'Insights', href: '/insights/' },
        { label: article.title, href: `/insights/${article.slug}/` },
      ])}
      <span class="eyebrow">For ${escapeHtml(article.buyer_target)}</span>
      <h1>${escapeHtml(article.title)}</h1>
      <p class="muted">By ${escapeHtml(article.author_name)}${article.published_at ? ` &middot; Published ${escapeHtml(article.published_at.slice(0, 10))}` : ''}</p>
      <div style="margin-top:1.5rem;">
        ${sanitizeRichHtml(article.body_html)}
      </div>
      <div class="panel panel--light" style="margin-top:2rem;">
        <a href="/request-proposal/${article.related_service ? `?service=${escapeHtml(article.related_service)}` : ''}" class="btn btn--primary">Request a proposal</a>
      </div>
    </div>
  </section>`;
}

export function renderNotFoundPage({ settings }) {
  return `
  <section class="section">
    <div class="container">
      <span class="eyebrow">404 — Page Not Found</span>
      <h1>We couldn’t find that page</h1>
      <p>The page may have moved or is not currently published. Use the links below or call <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a>.</p>
      <div class="hero__actions">
        <a href="/" class="btn btn--primary">Go to Home</a>
        <a href="/services/" class="btn btn--secondary">Explore Services</a>
        <a href="/request-proposal/" class="btn btn--secondary">Request a Proposal</a>
      </div>
    </div>
  </section>`;
}
