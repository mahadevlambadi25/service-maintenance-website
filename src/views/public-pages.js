import { SERVICE_FAMILIES, PRIVACY_NOTICE_VERSION } from '../config.js';
import { escapeHtml, sanitizeRichHtml } from '../lib/sanitize.js';
import { renderBeforeAfterPair, renderBreadcrumbs, renderFaqAccordion, renderResponsivePicture, renderSeasonalFeatureSlot } from './components.js';

export function renderHomePage({ rev, settings, approvedProjects, seasonalFeature, buildingEngineerLive }) {
  const homeFaqs = [
    {
      q: 'What types of commercial properties do you service?',
      a: 'We support industrial and warehouse facilities, retail centers, commercial offices, and multi-tenant commercial portfolios across Greater Phoenix.',
    },
    {
      q: 'How do I request a proposal?',
      a: 'Use our Request a Proposal form to share your property city or ZIP, service needed, and preferred contact method. Photos or an RFP PDF are optional, and no minimum project size is required.',
    },
    {
      q: 'Do you handle tenant improvements?',
      a: 'Yes. We manage commercial suite build-outs, alterations, white-shell lease-return turnovers, and final cleaning—coordinating licensed specialty trades where required.',
    },
    {
      q: 'Do you provide automated estimates or guaranteed emergency dispatch times?',
      a: 'No. Every scope is reviewed clearly in writing based on site access, operating hours, and trade requirements rather than automated pricing or unverified dispatch promises.',
    },
  ];

  return `
  <!-- 1. Hero (Photographic with Smooth Cream Gradient + Scope Review Starter) -->
  <section class="hero hero--photo" aria-labelledby="hero-title">
    <div class="container hero--photo__grid">
      <div class="hero--photo__content">
        <span class="eyebrow">Commercial Property Services &mdash; Greater Phoenix</span>
        <h1 id="hero-title">${escapeHtml(rev.hero_headline)}</h1>
        <p class="hero__lead">${escapeHtml(rev.hero_summary)}</p>
        <div class="hero__actions">
          <a href="${escapeHtml(rev.cta_route)}" class="btn btn--primary">${escapeHtml(rev.cta_label)} &rarr;</a>
          <a href="/services/" class="btn btn--secondary">Explore Our Services</a>
        </div>
        <div class="hero__trust-pills" aria-label="Verified credentials summary">
          <span class="hero__trust-pill">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            In-House &amp; Coordinated Trades
          </span>
          <span class="hero__trust-pill">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>
            Arizona ROC Licensed
          </span>
          <span class="hero__trust-pill">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
            Based in Tempe, AZ (Roots to 1989)
          </span>
        </div>
      </div>

      <aside class="hero-scope-card" aria-label="Start a scope review">
        <h2>Start a Scope Review</h2>
        <p>Select your commercial service need to open the proposal form with your scope preselected.</p>
        <form method="GET" action="/request-proposal/">
          <div class="field" style="margin-bottom:0.85rem;">
            <label for="hero-service-select" class="visually-hidden">Service category</label>
            <select id="hero-service-select" name="service" required>
              <option value="">Select a service...</option>
              ${SERVICE_FAMILIES.filter((s) => !s.conditional)
                .map((s) => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.label)}</option>`)
                .join('')}
            </select>
          </div>
          <button type="submit" class="btn btn--primary" style="width:100%;">Request a Proposal &rarr;</button>
        </form>
      </aside>
    </div>
  </section>

  <!-- 2. Quick Actions Strip -->
  <div class="container quick-strip-wrap">
    <nav class="quick-strip" aria-label="Quick customer actions">
      <a href="/request-service/" class="quick-strip__item">
        <span class="quick-strip__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg></span>
        <span class="quick-strip__text"><strong>Existing Client Service</strong><span>Maintenance routing</span></span>
      </a>
      <a href="/request-proposal/" class="quick-strip__item">
        <span class="quick-strip__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
        <span class="quick-strip__text"><strong>Request a Proposal</strong><span>New commercial scopes</span></span>
      </a>
      <a href="/service-area/" class="quick-strip__item">
        <span class="quick-strip__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg></span>
        <span class="quick-strip__text"><strong>Service Area</strong><span>Greater Phoenix metro</span></span>
      </a>
      <a href="/credentials/capabilities.pdf" class="quick-strip__item" download="Service-Maintenance-Capabilities.pdf" data-track="download_capabilities">
        <span class="quick-strip__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></span>
        <span class="quick-strip__text"><strong>Download Capabilities</strong><span>Ungated PDF</span></span>
      </a>
      <a href="tel:${escapeHtml(settings.phone_e164)}" class="quick-strip__item" data-track="phone_click">
        <span class="quick-strip__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg></span>
        <span class="quick-strip__text"><strong>Talk to Our Team</strong><span>${escapeHtml(settings.phone_display)}</span></span>
      </a>
    </nav>
  </div>

  <!-- 3. Our Services (4-Column Architectural Card Grid) -->
  <section class="section" aria-labelledby="pillars-title">
    <div class="container">
      <div class="section-head-row">
        <div>
          <span class="eyebrow">Our Services</span>
          <h2 id="pillars-title">Three core pillars &mdash; plus specialist paths</h2>
          <p class="section-header__lead">Comprehensive commercial property care, from day-to-day operations to suite improvements.</p>
        </div>
        <a href="/services/" style="font-weight:600;white-space:nowrap;">View All Services &rarr;</a>
      </div>

      <div class="grid-4">
        <article class="service-card">
          <span class="service-card__icon" aria-hidden="true"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
          <h3>Recurring Property Care</h3>
          <p>Day porter services, pressure washing, parking lot sweeping, and roof debris observations${buildingEngineerLive ? ' plus building engineer support' : ''}.</p>
          <a href="/services/day-porter/" class="service-card__link">Explore Services &rarr;</a>
        </article>

        <article class="service-card">
          <span class="service-card__icon" aria-hidden="true"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg></span>
          <h3>Commercial Maintenance &amp; Repairs</h3>
          <p>Responsive scoping for interior drywall, doors, hardware, lighting, plumbing coordination, and punch lists.</p>
          <a href="/services/commercial-maintenance/" class="service-card__link">Explore Services &rarr;</a>
        </article>

        <article class="service-card">
          <span class="service-card__icon" aria-hidden="true"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg></span>
          <h3>Tenant Improvements &amp; Make-Ready</h3>
          <p>Suite build-outs, selective demolition, white-shell lease-return turnovers, and in-house final cleaning.</p>
          <a href="/services/tenant-improvements/" class="service-card__link">Explore Services &rarr;</a>
        </article>

        <article class="service-card">
          <span class="service-card__icon" aria-hidden="true"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 20h20"/><path d="M5 20V8l7-5 7 5v12"/><path d="M9 20v-6h6v6"/></svg></span>
          <h3>Warehouse &amp; Exterior Scopes</h3>
          <p>Warehouse scrim &amp; insulation repair, dock concrete, bollards, stucco, gates, and site drainage upkeep.</p>
          <a href="/services/warehouse-repairs/" class="service-card__link">Explore Services &rarr;</a>
        </article>
      </div>
    </div>
  </section>

  <!-- Optional Configurable Seasonal Focus Placement -->
  ${renderSeasonalFeatureSlot(seasonalFeature)}

  <!-- 4. Our Process (Split Left Heading + Right 4-Step Timeline) -->
  <section class="section section--bone" aria-labelledby="process-title">
    <div class="container ref-split">
      <div>
        <span class="eyebrow">Our Process</span>
        <h2 id="process-title">A simple, transparent work process</h2>
        <p class="muted">From first inquiry to completion review, every scope stays clear, documented, and accountable.</p>
      </div>
      <ol class="ref-process-grid">
        <li class="ref-process-card">
          <span class="ref-process-card__num">01</span>
          <h3>Understand</h3>
          <p>Review your property location, operating hours, photos or plans, and approval structure.</p>
        </li>
        <li class="ref-process-card">
          <span class="ref-process-card__num">02</span>
          <h3>Define Scope</h3>
          <p>Confirm in-house tasks, specialty trade participation, access windows, and exclusions in writing.</p>
        </li>
        <li class="ref-process-card">
          <span class="ref-process-card__num">03</span>
          <h3>Coordinate</h3>
          <p>Sequence crews, equipment, and site protection around active tenants and deliveries.</p>
        </li>
        <li class="ref-process-card">
          <span class="ref-process-card__num">04</span>
          <h3>Close &amp; Review</h3>
          <p>Verify punch items, final cleaning, and closeout documentation with one accountable contact.</p>
        </li>
      </ol>
    </div>
  </section>

  <!-- 5. Properties We Serve (Split Left Heading + Right 4 Image Cards) -->
  <section class="section" aria-labelledby="properties-title">
    <div class="container ref-split">
      <div>
        <span class="eyebrow">Properties We Serve</span>
        <h2 id="properties-title">Commercial properties across Greater Phoenix</h2>
        <p class="muted">Tailored operational care for active industrial, retail, office, and multi-site portfolios.</p>
        <p style="margin-top:1rem;"><a href="/properties/" class="btn btn--secondary btn--compact">All Property Types &rarr;</a></p>
      </div>
      <div class="grid-4">
        <a href="/properties/industrial-warehouses/" class="prop-card">
          <img src="/assets/prop-industrial.jpg" alt="Generic Greater Phoenix industrial and warehouse facility exterior" class="prop-card__img" width="400" height="300">
          <span class="prop-card__body">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M2 20h20"/><path d="M4 20V9l8-4 8 4v11"/></svg>
            Industrial &amp; Warehouses
          </span>
        </a>
        <a href="/properties/retail-centers/" class="prop-card">
          <img src="/assets/prop-retail.jpg" alt="Generic Southwest commercial retail center exterior" class="prop-card__img" width="400" height="300">
          <span class="prop-card__body">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 9l2-5h14l2 5"/><path d="M5 9v11h14V9"/></svg>
            Retail Centers
          </span>
        </a>
        <a href="/properties/commercial-offices/" class="prop-card">
          <img src="/assets/prop-office.jpg" alt="Generic Greater Phoenix commercial office building exterior" class="prop-card__img" width="400" height="300">
          <span class="prop-card__body">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="4" y="2" width="16" height="20" rx="1"/><path d="M9 6h2"/><path d="M13 6h2"/><path d="M9 10h2"/><path d="M13 10h2"/></svg>
            Commercial Offices
          </span>
        </a>
        <a href="/property-managers/" class="prop-card">
          <img src="/assets/prop-portfolio.jpg" alt="Generic Greater Phoenix multi-tenant commercial business park" class="prop-card__img" width="400" height="300">
          <span class="prop-card__body">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><polyline points="17 11 19 13 23 9"/></svg>
            Property Portfolios
          </span>
        </a>
      </div>
    </div>
  </section>

  <!-- 6. Recent Projects (Approved Records Only; Truthful Empty State Otherwise) -->
  <section class="section section--bone" aria-labelledby="selected-work-title">
    <div class="container ref-split">
      <div>
        <span class="eyebrow">Recent Projects</span>
        <h2 id="selected-work-title">${approvedProjects.length > 0 ? 'Real work. Verified results.' : 'Real work. Verified evidence.'}</h2>
        <p class="muted">${approvedProjects.length > 0 ? 'Approved commercial maintenance and tenant improvement scopes.' : 'Case studies publish here only after completion verification and client naming permissions are recorded.'}</p>
        <p style="margin-top:1rem;"><a href="/projects/" class="btn btn--secondary btn--compact">View All Projects &rarr;</a></p>
      </div>
      ${
        approvedProjects.length > 0
          ? `<div class="grid-2">
              ${approvedProjects
                .slice(0, 2)
                .map(
                  (proj) => `<article class="panel panel--light">
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
                    <p style="font-size:0.92rem;">${escapeHtml(proj.agreed_scope)}</p>
                    <a href="/projects/${escapeHtml(proj.slug)}/" style="font-weight:600;">View Case Study &rarr;</a>
                  </article>`
                )
                .join('')}
            </div>`
          : `<div class="panel panel--light">
              <h3>Approved project case studies are published only with verified rights</h3>
              <p>Rather than displaying fabricated projects or placeholder testimonials, this showcase stays clear until client naming and media rights are approved. Meanwhile, procurement teams can review our verified Arizona ROC licensing and Capabilities Statement.</p>
              <div class="card-actions">
                <a href="/credentials/" class="btn btn--secondary btn--compact">View Credentials &rarr;</a>
                <a href="/request-proposal/">Discuss your property scope &rarr;</a>
              </div>
            </div>`
      }
    </div>
  </section>

  <!-- 7. Why Choose Us (5-Column Verified Strengths) -->
  <section class="section" aria-labelledby="diff-title">
    <div class="container">
      <div class="section-head-row">
        <div>
          <span class="eyebrow">Why Choose Us</span>
          <h2 id="diff-title">A reliable partner for your commercial property</h2>
        </div>
        <a href="/about/" style="font-weight:600;white-space:nowrap;">Our Company Story (Since 1989) &rarr;</a>
      </div>
      <div class="why-strip">
        <div class="why-item">
          <span class="why-item__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></span>
          <strong>Our roots date to 1989</strong>
        </div>
        <div class="why-item">
          <span class="why-item__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></span>
          <strong>In-House + Coordinated Trades</strong>
        </div>
        <div class="why-item">
          <span class="why-item__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
          <strong>Arizona ROC Licensed</strong>
        </div>
        <div class="why-item">
          <span class="why-item__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>
          <strong>Written Scope &amp; Closeout</strong>
        </div>
        <div class="why-item">
          <span class="why-item__icon" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg></span>
          <strong>Long-Term Property Care</strong>
        </div>
      </div>
    </div>
  </section>

  <!-- 8. Documentation & Resources (Verified Existing Routes & Capabilities PDF Only) -->
  <section class="section section--bone" aria-labelledby="docs-title">
    <div class="container ref-split">
      <div>
        <span class="eyebrow">Documentation &amp; Resources</span>
        <h2 id="docs-title">Verified, ready-to-use information</h2>
        <p class="muted">${escapeHtml(settings.legal_entity)} dba ${escapeHtml(settings.trading_name)} &middot; ${escapeHtml(settings.roc_numbers)}</p>
      </div>
      <div class="doc-grid">
        <a href="/credentials/capabilities.pdf" class="doc-tile" download="Service-Maintenance-Capabilities.pdf" data-track="download_capabilities">
          <div><strong>Capabilities Statement</strong><span>Download PDF (Ungated)</span></div>
          <span aria-hidden="true">&darr;</span>
        </a>
        <a href="/credentials/" class="doc-tile">
          <div><strong>Licensing &amp; Insurance</strong><span>Verify ROC &amp; COI process</span></div>
          <span aria-hidden="true">&rarr;</span>
        </a>
        <a href="/about/" class="doc-tile">
          <div><strong>Company Continuity</strong><span>Founded 1989 &middot; Promptitude Inc.</span></div>
          <span aria-hidden="true">&rarr;</span>
        </a>
        <a href="/service-area/" class="doc-tile">
          <div><strong>Service Area</strong><span>Greater Phoenix markets</span></div>
          <span aria-hidden="true">&rarr;</span>
        </a>
      </div>
    </div>
  </section>

  <!-- 9. Frequently Asked Questions -->
  <section class="section" aria-labelledby="home-faq-title">
    <div class="container ref-split">
      <div>
        <span class="eyebrow">FAQ</span>
        <h2 id="home-faq-title">Common questions</h2>
        <p class="muted">Clear answers about our services, process, and how we work with commercial property teams.</p>
        <p style="margin-top:1rem;"><a href="/services/" class="btn btn--secondary btn--compact">Explore All Services &rarr;</a></p>
      </div>
      <div>
        ${renderFaqAccordion(homeFaqs)}
      </div>
    </div>
  </section>

  <!-- 10. Dark Burgundy Proposal Banner -->
  <section class="section" aria-labelledby="final-cta-title" style="padding-top:0;">
    <div class="container">
      <div class="cta-banner">
        <div>
          <span class="eyebrow" style="color:#E4DCCE;">Get Started</span>
          <h2 id="final-cta-title">Tell us about your Greater Phoenix property</h2>
          <p style="margin-bottom:0;color:rgba(244,240,232,0.88);">Share your service need and property location—no automated estimate or minimum project size is required.</p>
        </div>
        <form class="cta-banner__form" method="GET" action="/request-proposal/">
          <select name="service" aria-label="Select service needed" class="cta-banner__full">
            <option value="">Select service needed...</option>
            ${SERVICE_FAMILIES.filter((s) => !s.conditional)
              .map((s) => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.label)}</option>`)
              .join('')}
          </select>
          <button type="submit" class="btn btn--secondary" style="background:var(--color-limestone);color:var(--color-carbon);border-color:var(--color-limestone);">Request a Proposal &rarr;</button>
          <a href="tel:${escapeHtml(settings.phone_e164)}" class="btn btn--ghost-light" data-track="phone_click">Call ${escapeHtml(settings.phone_display)}</a>
        </form>
      </div>
    </div>
  </section>
  `;
}

export function renderServiceOverviewPage({ buildingEngineerLive }) {
  const serviceFaqs = [
    {
      q: 'Is there a minimum project size or recurring contract requirement?',
      a: 'No minimum project size is published or required to start a conversation. We review single maintenance requests, multi-item repair lists, recurring porter routes, and tenant improvements.',
    },
    {
      q: 'Which work is self-performed vs. coordinated with specialty trades?',
      a: 'Core day porter care, general commercial maintenance, make-ready, and final suite cleaning are executed by our in-house team. Licensed specialty trades (such as electrical, plumbing, HVAC, or fire protection) are transparently coordinated when required by scope or code.',
    },
    {
      q: 'Do you support out-of-state property owners and asset managers?',
      a: 'Yes. Eligibility is based on where the commercial property is located (Greater Phoenix), and both US and international contact formats are supported.',
    },
    {
      q: 'Can existing clients submit maintenance requests without going through a sales proposal?',
      a: 'Yes. Active accounts can route maintenance needs directly through our Existing Customer Service Request form at /request-service/.',
    },
  ];

  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Services', href: '/services/' }])}
      <div class="section-header">
        <span class="eyebrow">Service Architecture</span>
        <h1>Commercial property services across Greater Phoenix</h1>
        <p class="section-header__lead">Organized by buyer need across three core pillars and specialist property paths. Every scope clearly distinguishes self-performed work from coordinated specialty trades.</p>
      </div>

      <div class="grid-3">
        <article class="panel">
          <div class="pillar-card__head">
            <span class="pillar-num">Pillar 01</span>
          </div>
          <h2>Recurring property care</h2>
          <p>Scheduled upkeep that keeps retail centers, business parks, and commercial sites presentable.</p>
          <ul class="scope-list">
            <li><a href="/services/day-porter/">Day porter services</a></li>
            <li><a href="/services/recurring-property-care/">Recurring property care</a> (pressure washing, sweeping, roof cleaning/observations)</li>
            ${buildingEngineerLive ? '<li><a href="/services/building-engineer/">Building engineer services</a> (scheduled operations support)</li>' : ''}
          </ul>
          <div class="card-actions">
            <a href="/request-proposal/?service=day-porter" class="btn btn--primary btn--compact">Request porter / care proposal</a>
          </div>
        </article>

        <article class="panel">
          <div class="pillar-card__head">
            <span class="pillar-num">Pillar 02</span>
          </div>
          <h2>Commercial maintenance &amp; repairs</h2>
          <p>Responsive, accountable scoping for single repairs, multi-task lists, and active industrial sites.</p>
          <ul class="scope-list">
            <li><a href="/services/commercial-maintenance/">Commercial maintenance &amp; repairs</a></li>
            <li><a href="/services/warehouse-repairs/">Warehouse &amp; industrial repairs</a> (scrim, insulation, docks, bollards)</li>
            <li><a href="/services/exterior-site-maintenance/">Exterior &amp; site maintenance</a> (stucco, concrete, gates, drainage)</li>
          </ul>
          <div class="card-actions">
            <a href="/request-proposal/?service=commercial-maintenance" class="btn btn--primary btn--compact">Request repair scope</a>
          </div>
        </article>

        <article class="panel">
          <div class="pillar-card__head">
            <span class="pillar-num">Pillar 03</span>
          </div>
          <h2>Tenant improvements &amp; make-ready</h2>
          <p>Commercial interior alterations, lease-return restoration, and coordinated suite build-outs.</p>
          <ul class="scope-list">
            <li><a href="/services/tenant-improvements/">Tenant improvements &amp; renovations</a></li>
            <li><a href="/services/tenant-move-outs/">Tenant move-outs &amp; make-ready</a></li>
          </ul>
          <div class="card-actions">
            <a href="/request-proposal/?service=tenant-improvements" class="btn btn--primary btn--compact">Request TI / make-ready bid</a>
          </div>
        </article>
      </div>

      <div class="panel panel--light" style="margin-top:2rem;">
        <h2>Need help choosing the right scope?</h2>
        <p>Already an active client needing maintenance routing? Use our <a href="/request-service/">Existing customer service request</a>. Otherwise, start a new inquiry and our team will route your property to the right owner.</p>
        <div class="hero__actions" style="margin-top:0.75rem;">
          <a href="/request-proposal/" class="btn btn--primary">Request a proposal</a>
          <a href="/properties/" class="btn btn--secondary">Browse by property type</a>
        </div>
      </div>

      <section style="margin-top:2.75rem;" aria-labelledby="services-faq-heading">
        <h2 id="services-faq-heading">Frequently asked questions</h2>
        ${renderFaqAccordion(serviceFaqs)}
      </section>
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

      ${
        project.cover_derivative_key || (isPreview && project.cover_asset_id)
          ? `<figure style="margin:1.25rem 0 0;max-width:54rem;">
              ${
                isPreview && project.cover_asset_id
                  ? `<img src="/admin/api/media/preview/${escapeHtml(project.cover_asset_id)}" alt="${escapeHtml(project.cover_alt || project.title)}" style="width:100%;max-height:420px;object-fit:cover;border-radius:var(--radius-lg);object-position:${escapeHtml(project.cover_focal_x ?? 50)}% ${escapeHtml(project.cover_focal_y ?? 50)}%;">`
                  : renderResponsivePicture({
                      src: `/media/${project.cover_derivative_key}`,
                      variantsJson: project.cover_variants_json,
                      alt: project.cover_alt || project.title,
                      width: 960,
                      height: 540,
                      focalX: project.cover_focal_x ?? 50,
                      focalY: project.cover_focal_y ?? 50,
                      loading: 'eager',
                      style: 'width:100%;max-height:420px;object-fit:cover;border-radius:var(--radius-lg);',
                    })
              }
            </figure>`
          : ''
      }

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

      <section style="margin-top:2.5rem;" aria-labelledby="cred-faq-heading">
        <h2 id="cred-faq-heading">Procurement &amp; vendor onboarding FAQ</h2>
        ${renderFaqAccordion([
          {
            q: 'Can we verify Arizona ROC license status independently?',
            a: `Yes. Current active license classifications for ${settings.legal_entity} (${settings.roc_numbers}) can be verified directly through the Arizona Registrar of Contractors at roc.az.gov.`,
          },
          {
            q: 'How do property managers request a Certificate of Insurance (COI) or W-9?',
            a: 'Use the "Request Insurance / Onboarding Docs" button above (which pre-selects Procurement / vendor documentation) or call our office line during business hours.',
          },
          {
            q: 'Does holding a contractor license mean all trades are self-performed?',
            a: 'No. We clearly distinguish in-house recurring care, general repairs, make-ready, and final cleaning from licensed specialty trades coordinated for electrical, plumbing, HVAC, or fire protection scopes.',
          },
        ])}
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
      <div class="section-header" style="max-width:52rem;">
        <span class="eyebrow">New Commercial Inquiry</span>
        <h1>Request a proposal or property assessment</h1>
        <p class="section-header__lead">Share your contact details, commercial property location, and project scope in three quick steps. No automated estimate or minimum project size is implied.</p>
      </div>

      <div id="form-error-summary" class="error-summary" hidden tabindex="-1" role="alert">
        <h2>Please review the highlighted fields</h2>
        <ul id="form-error-list"></ul>
      </div>

      <div id="form-server-failure" class="status-banner status-banner--error" hidden role="alert">
        <strong>Submission was not confirmed.</strong> Your entries have been preserved below so you can retry safely or call us directly at
        <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)}).
      </div>

      <div class="inquiry-layout inquiry-layout--proposal">
        <div class="proposal-card">
          <ol class="proposal-stepper" id="proposal-stepper" aria-label="Proposal request steps">
            <li class="proposal-stepper__item" data-step-indicator="1" data-state="active" aria-current="step">
              <span class="proposal-stepper__num">1</span>
              <span class="proposal-stepper__label">
                <strong>Step 1</strong>
                <span>Contact Info</span>
              </span>
            </li>
            <li class="proposal-stepper__item" data-step-indicator="2" data-state="upcoming">
              <span class="proposal-stepper__num">2</span>
              <span class="proposal-stepper__label">
                <strong>Step 2</strong>
                <span>Property &amp; Service</span>
              </span>
            </li>
            <li class="proposal-stepper__item" data-step-indicator="3" data-state="upcoming">
              <span class="proposal-stepper__num">3</span>
              <span class="proposal-stepper__label">
                <strong>Step 3</strong>
                <span>Requirements &amp; Review</span>
              </span>
            </li>
          </ol>

          <form id="proposal-form" class="form-stack form-stack--wide" method="POST" action="/api/inquiries" enctype="multipart/form-data" novalidate data-form-type="proposal">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <input type="hidden" name="idempotency_key" id="idempotency_key" value="">
            <input type="hidden" name="privacy_notice_version" value="${escapeHtml(PRIVACY_NOTICE_VERSION)}">
            <!-- Accessible honeypot for abuse control -->
            <div class="visually-hidden" aria-hidden="true">
              <label for="website_url_hp">Leave blank</label>
              <input type="text" id="website_url_hp" name="website_url_hp" tabindex="-1" autocomplete="off">
            </div>

            <!-- STEP 1: Contact Information -->
            <section class="proposal-step" data-step="1" aria-labelledby="step-1-heading">
              <div class="proposal-step__header">
                <h2 id="step-1-heading" tabindex="-1">Step 1: Contact Information</h2>
                <p>Tell us who to follow up with and your preferred way to be reached.</p>
              </div>

              <div class="field-row">
                <div class="field">
                  <label for="name">Your name <span aria-hidden="true">*</span></label>
                  <input type="text" id="name" name="name" required maxlength="100" autocomplete="name" data-error="err-name">
                  <div id="err-name" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your name (up to 100 characters).</div>
                </div>

                <div class="field">
                  <label for="company">Company or organization <span aria-hidden="true">*</span></label>
                  <input type="text" id="company" name="company" required maxlength="150" autocomplete="organization" aria-describedby="hint-company" data-error="err-company">
                  <span id="hint-company" class="hint">Property firm, owner, or tenant business name.</span>
                  <div id="err-company" class="error-msg"><span role="img" aria-label="Error">!</span> Enter your company or organization name.</div>
                </div>
              </div>

              <fieldset class="choice-group">
                <legend>Preferred contact method <span aria-hidden="true">*</span></legend>
                <div class="field-row">
                  <div class="choice-row">
                    <input type="radio" id="pref-email" name="preferred_contact_method" value="email" checked>
                    <label for="pref-email">Email</label>
                  </div>
                  <div class="choice-row">
                    <input type="radio" id="pref-phone" name="preferred_contact_method" value="telephone">
                    <label for="pref-phone">Telephone</label>
                  </div>
                </div>
              </fieldset>

              <div class="field-row">
                <div class="field">
                  <label for="email">Email address <span id="email-req-mark" aria-hidden="true">*</span></label>
                  <input type="email" id="email" name="email" autocomplete="email" inputmode="email" autocorrect="off" autocapitalize="none" spellcheck="false" aria-describedby="hint-email" data-error="err-email" required>
                  <span id="hint-email" class="hint">Personal or business email domains are accepted.</span>
                  <div id="err-email" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid email address (for example, name@company.com).</div>
                </div>

                <div class="field">
                  <label for="telephone">Telephone <span id="phone-req-mark" class="visually-hidden">(optional when email selected)</span></label>
                  <input type="tel" id="telephone" name="telephone" autocomplete="tel" inputmode="tel" aria-describedby="hint-phone" data-error="err-telephone">
                  <span id="hint-phone" class="hint">US or international formats supported for remote owners.</span>
                  <div id="err-telephone" class="error-msg"><span role="img" aria-label="Error">!</span> Enter a valid telephone number (7 to 15 digits).</div>
                </div>
              </div>

              <div class="proposal-step__actions proposal-step__actions--end">
                <button type="button" class="btn btn--primary btn--lg" data-next-step="2">Continue to Property &amp; Service &rarr;</button>
              </div>
            </section>

            <!-- STEP 2: Property & Service Information -->
            <section class="proposal-step" data-step="2" aria-labelledby="step-2-heading">
              <div class="proposal-step__header">
                <h2 id="step-2-heading" tabindex="-1">Step 2: Property &amp; Service Information</h2>
                <p>Select the commercial service needed and tell us where the property is located.</p>
              </div>

              <div class="field-row">
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
                  <input type="text" id="property_city_or_zip" name="property_city_or_zip" required maxlength="120" aria-describedby="hint-prop-loc" data-error="err-prop-loc">
                  <span id="hint-prop-loc" class="hint">Location of the property (even if your office is out of state).</span>
                  <div id="err-prop-loc" class="error-msg"><span role="img" aria-label="Error">!</span> Enter the property city or ZIP.</div>
                </div>
              </div>

              <div class="field-row">
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
              </div>

              <div id="time-sensitive-note" class="status-banner status-banner--warning" hidden>
                <strong>Time-sensitive inquiry note:</strong> Our monitored office line is <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)}). Submitting this form routes your request for operational review; it does not imply immediate dispatch.
              </div>

              <div class="choice-row" style="margin-bottom:1.25rem;">
                <input type="checkbox" id="multiple_properties" name="multiple_properties">
                <label for="multiple_properties">This inquiry covers multiple commercial properties</label>
              </div>

              <div id="multi-prop-fields" class="panel" hidden style="margin-bottom:1.4rem;">
                <div class="field-row">
                  <div class="field" style="margin-bottom:0;">
                    <label for="site_count">Approximate number of sites</label>
                    <input type="text" id="site_count" name="site_count" maxlength="40">
                  </div>
                  <div class="field" style="margin-bottom:0;">
                    <label for="coverage_detail">Cities / portfolio overview</label>
                    <input type="text" id="coverage_detail" name="coverage_detail" maxlength="300">
                  </div>
                </div>
              </div>

              <!-- Conditional TI/RFP Section (shown only for Tenant Improvements / Move-Outs) -->
              <div id="ti-conditional-fields" class="panel" hidden style="margin-bottom:1.4rem;">
                <h3 style="margin-bottom:0.85rem;">Tenant Improvement / RFP Details (Optional)</h3>
                <div class="field-row">
                  <div class="field"><label for="ti_property_address">Property street address</label><input type="text" id="ti_property_address" name="ti_property_address" maxlength="200"></div>
                  <div class="field"><label for="ti_occupancy">Space condition</label>
                    <select id="ti_occupancy" name="ti_occupancy"><option value="">Select...</option><option value="occupied">Occupied</option><option value="vacant">Vacant</option><option value="partial">Partially occupied</option></select>
                  </div>
                </div>
                <div class="field-row">
                  <div class="field"><label for="ti_plans_available">Architectural plans / drawings status</label>
                    <select id="ti_plans_available" name="ti_plans_available">
                      <option value="">Select...</option>
                      <option value="Complete plans available">Complete plans available</option>
                      <option value="Preliminary sketches only">Preliminary sketches only</option>
                      <option value="No plans yet — scope estimate needed">No plans yet — scope estimate needed</option>
                    </select>
                  </div>
                  <div class="field"><label for="ti_bid_due_date">Bid due date (if RFP)</label><input type="date" id="ti_bid_due_date" name="ti_bid_due_date"></div>
                </div>
                <div class="field-row">
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
                </div>
                <div class="field" style="margin-bottom:0;"><label for="ti_landlord_involvement">Owner / landlord approval contact</label><input type="text" id="ti_landlord_involvement" name="ti_landlord_involvement" maxlength="120"></div>
              </div>

              <!-- Conditional Recurring Care Section (shown only for Day Porter / Recurring Property Care) -->
              <div id="recurring-conditional-fields" class="panel" hidden style="margin-bottom:1.4rem;">
                <h3 style="margin-bottom:0.85rem;">Recurring Program Details (Optional)</h3>
                <div class="field-row">
                  <div class="field"><label for="rc_frequency">Desired service frequency</label><input type="text" id="rc_frequency" name="rc_frequency" maxlength="60"></div>
                  <div class="field"><label for="rc_site_size">Approximate site size / building count</label><input type="text" id="rc_site_size" name="rc_site_size" maxlength="80"></div>
                </div>
                <div class="field" style="margin-bottom:0;"><label for="rc_current_arrangement">Current service arrangement &amp; main concerns</label><input type="text" id="rc_current_arrangement" name="rc_current_arrangement" maxlength="200"></div>
              </div>

              <div class="proposal-step__actions">
                <button type="button" class="btn btn--secondary" data-prev-step="1">&larr; Back</button>
                <button type="button" class="btn btn--primary btn--lg" data-next-step="3">Continue to Requirements &amp; Review &rarr;</button>
              </div>
            </section>

            <!-- STEP 3: Project Requirements & Review -->
            <section class="proposal-step" data-step="3" aria-labelledby="step-3-heading">
              <div class="proposal-step__header">
                <h2 id="step-3-heading" tabindex="-1">Step 3: Project Requirements &amp; Review</h2>
                <p>Describe what needs attention, attach optional photos or RFP files, and review your summary.</p>
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

              <div class="review-summary" id="proposal-review-summary" aria-label="Review your proposal request">
                <h3 class="review-summary__title">Review Your Information</h3>
                <div class="review-group">
                  <div class="review-group__head">
                    <h4>Contact Information</h4>
                    <button type="button" class="review-edit-btn" data-goto-step="1">Edit</button>
                  </div>
                  <dl class="review-dl" id="review-contact-dl"></dl>
                </div>
                <div class="review-group">
                  <div class="review-group__head">
                    <h4>Property &amp; Service</h4>
                    <button type="button" class="review-edit-btn" data-goto-step="2">Edit</button>
                  </div>
                  <dl class="review-dl" id="review-property-dl"></dl>
                </div>
                <div class="review-group" id="review-conditional-group" hidden>
                  <div class="review-group__head">
                    <h4 id="review-conditional-title">Program Details</h4>
                    <button type="button" class="review-edit-btn" data-goto-step="2">Edit</button>
                  </div>
                  <dl class="review-dl" id="review-conditional-dl"></dl>
                </div>
                <div class="review-group">
                  <div class="review-group__head">
                    <h4>Requirements &amp; Files</h4>
                  </div>
                  <dl class="review-dl" id="review-scope-dl"></dl>
                </div>
              </div>

              <div class="panel panel--light" style="margin-bottom:1.25rem;">
                <p style="font-size:0.9rem;margin-bottom:0.75rem;">
                  <strong>Privacy Notice:</strong> Information submitted here is used to review and respond to your commercial service inquiry (<a href="/privacy/">Privacy Policy</a>).
                </p>
                <div class="choice-row">
                  <input type="checkbox" id="marketing_opt_in" name="marketing_opt_in">
                  <label for="marketing_opt_in">Optional: Send occasional seasonal property care reminders from Service Maintenance (never required to request a proposal).</label>
                </div>
              </div>

              <div class="proposal-step__actions">
                <button type="button" class="btn btn--secondary" data-prev-step="2">&larr; Back</button>
                <button type="submit" class="btn btn--primary btn--lg" id="submit-proposal-btn">Submit Proposal Request &rarr;</button>
              </div>
            </section>
          </form>
        </div>

        <aside class="inquiry-sidebar" aria-label="Proposal expectations and direct contact">
          <div class="next-steps-card">
            <span class="eyebrow">What Happens Next</span>
            <h2 style="font-size:1.35rem;margin-bottom:0.25rem;">Clear review &mdash; no automated quotes</h2>
            <p style="font-size:0.9rem;color:var(--color-muted-stone);margin-bottom:0;">Every commercial inquiry is reviewed directly by our Greater Phoenix operations and estimating team.</p>
            <ol class="next-steps-list">
              <li>
                <span class="next-steps-list__num" aria-hidden="true">1</span>
                <div><strong style="color:var(--color-carbon);display:block;">Recorded receipt</strong>You receive an immediate reference ID upon submission.</div>
              </li>
              <li>
                <span class="next-steps-list__num" aria-hidden="true">2</span>
                <div><strong style="color:var(--color-carbon);display:block;">Operations routing</strong>Your property is routed to the appropriate estimating, TI, or day porter lead.</div>
              </li>
              <li>
                <span class="next-steps-list__num" aria-hidden="true">3</span>
                <div><strong style="color:var(--color-carbon);display:block;">Written scope follow-up</strong>We follow up during ${escapeHtml(settings.hours_display)} to confirm site access, drawings, or walkthrough needs.</div>
              </li>
            </ol>
            <hr style="border:none;border-top:1px solid var(--border-subtle);margin:1.25rem 0;">
            <p style="font-size:0.92rem;margin-bottom:0.5rem;">
              <strong>Direct Office Line:</strong><br>
              <a href="tel:${escapeHtml(settings.phone_e164)}" data-track="phone_click" style="font-weight:600;">${escapeHtml(settings.phone_display)}</a><br>
              <span style="font-size:0.84rem;color:var(--color-muted-stone);">${escapeHtml(settings.hours_display)}</span>
            </p>
            <p style="font-size:0.86rem;color:var(--color-muted-stone);margin-bottom:0;">
              Active client needing routine maintenance? <a href="/request-service/">Use the existing customer request form</a>.
            </p>
          </div>
        </aside>
      </div>

      <section style="margin-top:2.75rem;" aria-labelledby="prop-faq-heading">
        <h2 id="prop-faq-heading">Proposal &amp; scoping FAQ</h2>
        ${renderFaqAccordion([
          {
            q: 'Do I need architectural drawings or site photos before submitting?',
            a: 'No. Photos, RFP PDFs, and drawings are optional. If you have large plans or HEIC files, submit your details without attachments and our team can send a secure upload link.',
          },
          {
            q: 'Can out-of-state property owners or remote asset managers submit a request?',
            a: 'Yes. As long as the commercial property is in Greater Phoenix, both US and international telephone numbers and personal or business emails are accepted.',
          },
          {
            q: 'Does submitting this form commit us to a contract or generate an automated price?',
            a: 'No. Every commercial scope is reviewed in person or by phone/photos with clear written inclusions and exclusions before any work is authorized.',
          },
        ])}
      </section>
    </div>
  </section>`;
}

export function renderServiceRequestFormPage({ settings, csrfToken }) {
  return `
  <section class="section">
    <div class="container">
      ${renderBreadcrumbs([{ label: 'Home', href: '/' }, { label: 'Existing customer service', href: '/request-service/' }])}
      <div class="section-header" style="max-width:52rem;">
        <span class="eyebrow">Operations Routing</span>
        <h1>Existing customer service request</h1>
        <p class="section-header__lead">Submit a maintenance or property care request for an active commercial account. Submitting this form routes your request to operations for review and does not claim an approved work order or guaranteed dispatch time.</p>
      </div>

      <div id="form-error-summary" class="error-summary" hidden tabindex="-1" role="alert">
        <h2>Please review the highlighted fields</h2>
        <ul id="form-error-list"></ul>
      </div>

      <div id="form-server-failure" class="status-banner status-banner--error" hidden role="alert">
        <strong>Request was not confirmed.</strong> Your entries are preserved below. Call our office line at <a href="tel:${escapeHtml(settings.phone_e164)}">${escapeHtml(settings.phone_display)}</a> (${escapeHtml(settings.hours_display)}).
      </div>

      <div class="inquiry-layout inquiry-layout--proposal">
        <div class="proposal-card">
          <form id="service-request-form" class="form-stack form-stack--wide" method="POST" action="/api/service-requests" novalidate data-form-type="service_request">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <input type="hidden" name="idempotency_key" id="idempotency_key" value="">

            <div class="field-row">
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
            </div>

            <fieldset class="choice-group">
              <legend>Preferred contact method <span aria-hidden="true">*</span></legend>
              <div class="field-row">
                <div class="choice-row">
                  <input type="radio" id="sr-pref-email" name="preferred_contact_method" value="email" checked>
                  <label for="sr-pref-email">Email</label>
                </div>
                <div class="choice-row">
                  <input type="radio" id="sr-pref-phone" name="preferred_contact_method" value="telephone">
                  <label for="sr-pref-phone">Telephone</label>
                </div>
              </div>
            </fieldset>

            <div class="field-row">
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
            </div>

            <div class="field-row">
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

            <div class="proposal-step__actions proposal-step__actions--end">
              <button type="submit" class="btn btn--primary btn--lg" id="submit-sr-btn">Send Service Request &rarr;</button>
            </div>
          </form>
        </div>

        <aside class="inquiry-sidebar" aria-label="Operations routing details">
          <div class="next-steps-card">
            <span class="eyebrow">Operations Routing</span>
            <h2 style="font-size:1.35rem;margin-bottom:0.25rem;">Active account support</h2>
            <ol class="next-steps-list">
              <li><span class="next-steps-list__num" aria-hidden="true">1</span><div><strong style="color:var(--color-carbon);display:block;">Direct operations queue</strong>Routed with your optional PO or job reference number.</div></li>
              <li><span class="next-steps-list__num" aria-hidden="true">2</span><div><strong style="color:var(--color-carbon);display:block;">Clear review</strong>Submitting records your request for review and does not claim an approved work order or guaranteed dispatch time.</div></li>
            </ol>
            <hr style="border:none;border-top:1px solid var(--border-subtle);margin:1.25rem 0;">
            <p style="font-size:0.92rem;margin-bottom:0.5rem;">
              <strong>Direct Office Line:</strong><br>
              <a href="tel:${escapeHtml(settings.phone_e164)}" data-track="phone_click" style="font-weight:600;">${escapeHtml(settings.phone_display)}</a><br>
              <span style="font-size:0.84rem;color:var(--color-muted-stone);">${escapeHtml(settings.hours_display)}</span>
            </p>
            <p style="font-size:0.86rem;color:var(--color-muted-stone);margin-bottom:0;">
              New commercial project or property? <a href="/request-proposal/">Request a proposal instead</a>.
            </p>
          </div>
        </aside>
      </div>
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
