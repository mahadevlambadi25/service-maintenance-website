import { escapeHtml } from '../lib/sanitize.js';

export function renderBreadcrumbs(items) {
  return `<nav class="breadcrumbs" aria-label="Breadcrumb">
    <ol>
      ${items
        .map((item, i) =>
          i === items.length - 1
            ? `<li aria-current="page">${escapeHtml(item.label)}</li>`
            : `<li><a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a></li>`
        )
        .join('')}
    </ol>
  </nav>`;
}

export function renderSeasonalFeatureSlot(campaign) {
  if (!campaign) return '';
  const hasImg = Boolean(campaign.asset && campaign.asset.public_derivative_key);
  return `<section class="section" aria-label="Seasonal focus">
    <div class="container">
      <div class="seasonal-feature${hasImg ? ' seasonal-feature--with-image' : ''}"
           data-campaign-id="${escapeHtml(campaign.campaign_id)}"
           data-placement-id="${escapeHtml(campaign.placement_slot)}"
           data-revision="${escapeHtml(campaign.content_revision)}">
        <div>
          <span class="eyebrow">Seasonal Focus</span>
          <h2>${escapeHtml(campaign.heading)}</h2>
          <p>${escapeHtml(campaign.summary)}</p>
          <a href="${escapeHtml(campaign.cta_destination)}" class="btn btn--primary" data-campaign-cta="${escapeHtml(campaign.placement_slot)}">${escapeHtml(campaign.cta_label)}</a>
        </div>
        ${
          hasImg
            ? `<div>
                <img src="/media/${escapeHtml(campaign.asset.public_derivative_key)}"
                     alt="${escapeHtml(campaign.asset.alt_text || campaign.heading)}"
                     width="${escapeHtml(campaign.asset.width)}"
                     height="${escapeHtml(campaign.asset.height)}"
                     loading="lazy"
                     style="object-fit:cover;object-position:${escapeHtml(campaign.asset.focal_x)}% ${escapeHtml(campaign.asset.focal_y)}%;border-radius:2px;">
              </div>`
            : ''
        }
      </div>
    </div>
  </section>`;
}

export function renderResponsivePicture({ src, variantsJson, alt, width, height, focalX = 50, focalY = 50, style = '', loading = 'lazy' }) {
  let variants = null;
  if (variantsJson) {
    try { variants = typeof variantsJson === 'string' ? JSON.parse(variantsJson) : variantsJson; } catch {}
  }
  const styleAttr = `object-fit:cover;object-position:${escapeHtml(focalX ?? 50)}% ${escapeHtml(focalY ?? 50)}%;${style}`;
  if (!variants || !variants.webp || !variants.jpeg || src.startsWith('/admin/api/media/preview/')) {
    return `<img src="${escapeHtml(src)}" alt="${escapeHtml(alt)}" width="${escapeHtml(width || 800)}" height="${escapeHtml(height || 600)}" style="${styleAttr}" loading="${escapeHtml(loading)}">`;
  }
  const webpSrcset = [
    variants.webp.mobile ? `/media/${variants.webp.mobile} 480w` : '',
    variants.webp.tablet ? `/media/${variants.webp.tablet} 960w` : '',
    variants.webp.desktop ? `/media/${variants.webp.desktop} 1600w` : '',
  ]
    .filter(Boolean)
    .join(', ');
  const jpgSrcset = [
    variants.jpeg.mobile ? `/media/${variants.jpeg.mobile} 480w` : '',
    variants.jpeg.tablet ? `/media/${variants.jpeg.tablet} 960w` : '',
    variants.jpeg.desktop ? `/media/${variants.jpeg.desktop} 1600w` : '',
  ]
    .filter(Boolean)
    .join(', ');

  return `<picture>
    ${webpSrcset ? `<source type="image/webp" srcset="${escapeHtml(webpSrcset)}" sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw">` : ''}
    <img src="${escapeHtml(src)}"${jpgSrcset ? ` srcset="${escapeHtml(jpgSrcset)}" sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw"` : ''} alt="${escapeHtml(alt)}" width="${escapeHtml(width || 800)}" height="${escapeHtml(height || 600)}" style="${styleAttr}" loading="${escapeHtml(loading)}">
  </picture>`;
}

/**
 * Renders Before/After comparison:
 * PRD Section 19.03:
 * - Static labeled side-by-side on wider screens, stacked Before then After on mobile by default.
 */
export function renderBeforeAfterPair(pair, index, isPreview = false) {
  const imgPrefix = isPreview ? '/admin/api/media/preview/' : '/media/';
  const beforeSrc = isPreview ? `${imgPrefix}${pair.before_asset_id}` : `${imgPrefix}${pair.before_derivative_key}`;
  const afterSrc = isPreview ? `${imgPrefix}${pair.after_asset_id}` : `${imgPrefix}${pair.after_derivative_key}`;

  return `<article class="ba-pair" aria-labelledby="ba-title-${index}">
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:0.5rem;margin-bottom:0.85rem;">
      <h3 id="ba-title-${index}" style="margin:0;">${escapeHtml(pair.pair_title || `Comparison ${index + 1}`)}</h3>
      ${pair.viewpoint_note ? `<span class="muted" style="font-size:0.88rem;">Viewpoint: ${escapeHtml(pair.viewpoint_note)}</span>` : ''}
    </div>

    <div class="ba-pair__grid">
      <figure class="ba-figure">
        <span class="ba-figure__label">Before</span>
        ${renderResponsivePicture({
          src: beforeSrc,
          variantsJson: isPreview ? null : pair.before_variants_json,
          alt: pair.before_alt || `Before condition: ${pair.pair_title}`,
          width: pair.before_width || 800,
          height: pair.before_height || 600,
          focalX: pair.before_focal_x ?? 50,
          focalY: pair.before_focal_y ?? 50,
        })}
        <figcaption>
          ${escapeHtml(pair.before_caption || 'Documented prior condition.')}
          ${pair.before_capture_date ? ` <span class="muted">(${escapeHtml(pair.before_capture_date)})</span>` : ''}
        </figcaption>
      </figure>

      <figure class="ba-figure">
        <span class="ba-figure__label ba-figure__label--after">After</span>
        ${renderResponsivePicture({
          src: afterSrc,
          variantsJson: isPreview ? null : pair.after_variants_json,
          alt: pair.after_alt || `Completed condition: ${pair.pair_title}`,
          width: pair.after_width || 800,
          height: pair.after_height || 600,
          focalX: pair.after_focal_x ?? 50,
          focalY: pair.after_focal_y ?? 50,
        })}
        <figcaption>
          ${escapeHtml(pair.after_caption || 'Completed work.')}
          ${pair.after_capture_date ? ` <span class="muted">(${escapeHtml(pair.after_capture_date)})</span>` : ''}
        </figcaption>
      </figure>
    </div>
  </article>`;
}
