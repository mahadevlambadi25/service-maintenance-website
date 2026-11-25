/**
 * Pure Node.js PDF 1.4 Generator for Service Maintenance's ungated Capabilities Statement (/credentials/capabilities.pdf).
 * Dynamically pulls verified data from canonical business_settings so it always stays in sync.
 */

function escapePdfText(str) {
  return String(str || '')
    .replace(/[^\x20-\x7E]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrapText(text, maxChars = 84) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > maxChars) {
      if (line) lines.push(line);
      line = w;
    } else {
      line = (line + ' ' + w).trim();
    }
  }
  if (line) lines.push(line);
  return lines;
}

export function generateCapabilitiesPdf(settings) {
  const lines = [];
  const addHeading = (txt) => {
    lines.push({ text: txt, font: 'F2', size: 13, gapBefore: 10, gapAfter: 4 });
  };
  const addBody = (txt) => {
    for (const l of wrapText(txt, 86)) {
      lines.push({ text: l, font: 'F1', size: 10, gapBefore: 0, gapAfter: 2 });
    }
  };

  lines.push({ text: 'SERVICE MAINTENANCE — CAPABILITIES STATEMENT', font: 'F2', size: 16, gapBefore: 0, gapAfter: 4 });
  lines.push({
    text: `${settings.trading_name} (a trading name of ${settings.legal_entity}) | Greater Phoenix, Arizona`,
    font: 'F1',
    size: 10,
    gapBefore: 0,
    gapAfter: 10,
  });

  addHeading('1. Company Overview & Continuity');
  addBody(
    'Our roots date to 1989 when Patrick Voita founded Service Maintenance providing day porter services. Original incorporation occurred in 1992, tenant improvement capabilities expanded under co-owner and general manager Greg Vandenberg starting in 2006, and Promptitude Inc. acquired the business on June 29, 2020. Today Service Maintenance delivers recurring property care, commercial repairs, and tenant improvements through in-house technicians and coordinated specialty subcontractors.'
  );

  addHeading('2. Three Core Service Pillars');
  addBody('• Recurring Property Care: Day porter services, building operations support, pressure washing, parking lot sweeping, roof cleaning/visual observations, and coordinated exterior recurring maintenance.');
  addBody('• Commercial Maintenance & Repairs: Interior repairs (drywall, paint, ceilings, doors/hardware), lighting/electrical troubleshooting, plumbing repairs, flooring/finishes, concrete/masonry, warehouse scrim & insulation, welding/fabrication, and final/suite cleaning.');
  addBody('• Tenant Improvements & Make-Ready: Commercial interior alterations, tenant move-outs, white-shell/put-back scopes, trade sequencing, permit/design coordination where required, and documented closeout.');

  addHeading('3. Primary Property Types & Service Area');
  addBody('Primary properties served: Industrial, warehouse, and distribution facilities; retail centers; office and multi-tenant commercial buildings; and multi-site commercial portfolios across Greater Phoenix.');

  addHeading('4. Verified Licensing, Insurance & Procurement');
  addBody(`Legal Entity: ${settings.legal_entity} (dba ${settings.trading_name})`);
  addBody(`Arizona ROC Numbers: ${settings.roc_numbers} (Verify active status & classifications via AZ Registrar of Contractors). License badges do not imply every trade is self-performed.`);
  addBody(`Insurance: ${settings.insurance_statement}. Coverage includes general liability, umbrella, commercial auto, and workers compensation; certificates furnished upon request.`);

  addHeading('5. Monitored Company Contact');
  addBody(`Telephone: ${settings.phone_display} | Office Hours (${settings.timezone}): ${settings.hours_display}`);
  addBody(`Office Reference: ${settings.address_display}`);
  addBody(`Inquiries & Documentation Requests: ${settings.website_url}/credentials/ | ${settings.website_url}/request-proposal/`);

  // Build PDF content stream
  let stream = 'BT\n';
  let y = 745;
  for (const item of lines) {
    y -= item.gapBefore;
    if (y < 52) break;
    stream += `/${item.font} ${item.size} Tf\n1 0 0 1 54 ${y} Tm\n(${escapePdfText(item.text)}) Tj\n`;
    y -= item.size + item.gapAfter;
  }
  stream += 'ET\n';

  const objects = [];
  objects.push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
  objects.push('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n');
  objects.push(
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n'
  );
  objects.push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
  objects.push('5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n');
  objects.push(`6 0 obj\n<< /Length ${Buffer.byteLength(stream, 'ascii')} >>\nstream\n${stream}endstream\nendobj\n`);

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (const obj of objects) {
    offsets.push(Buffer.byteLength(pdf, 'ascii'));
    pdf += obj;
  }
  const xrefPos = Buffer.byteLength(pdf, 'ascii');
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objects.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;

  return Buffer.from(pdf, 'ascii');
}
