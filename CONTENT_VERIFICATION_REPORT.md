# Content Verification Report — Service Maintenance Website

**Date:** 2026-11-27  
**Scope:** Public Website Redesign (Reference-Matched Layout)

---

## 1. Verified Business Information (Used on Public Website)

| Item | Verified Value | Source |
| :--- | :--- | :--- |
| **Trading Name** | Service Maintenance | `business_settings.trading_name` / `seed.js` |
| **Legal Entity** | Promptitude Inc. | `business_settings.legal_entity` / `seed.js` |
| **Founding & Continuity** | Founded 1989 (Patrick Voita), incorporated 1992, Greg Vandenberg joined 2006, acquired by Promptitude Inc. June 29, 2020 | `seed.js` / `/about/` |
| **Arizona ROC Numbers** | `ROC 334982` · `ROC 340441` · `ROC 349261` (exact string in `business_settings.roc_numbers`) | `business_settings.roc_numbers` |
| **Telephone** | `(480) 423-9196` (`+14804239196`) | `business_settings.phone_display` |
| **Office Hours** | `Monday – Friday, 7:00 AM – 5:00 PM (America/Phoenix)` | `business_settings.hours_display` |
| **Office Address Reference** | `2105 S Hardy Dr., Suite 17, Tempe, AZ` | `business_settings.address_display` |
| **Service Categories** | Recurring Property Care (Day Porter, Recurring Care, conditional Building Engineer), Commercial Maintenance & Repairs (Commercial Maintenance, Warehouse Repairs, Exterior & Site Maintenance), Tenant Improvements & Make-Ready (Tenant Improvements, Tenant Move-Outs) | `src/config.js` (`SERVICE_FAMILIES`) |
| **Properties Served** | Industrial & Warehouses, Retail Centers, Commercial Offices, Property Management Portfolios | `seed.js` / `public-pages.js` |
| **Downloadable Document** | Capabilities Statement PDF (`/credentials/capabilities.pdf`) | `src/lib/pdf-generator.js` |

---

## 2. Intentionally Omitted / Not Invented (From Reference Screenshot)

To comply strictly with the **Real Content Only** policy, the following reference-only elements were **excluded or replaced with real equivalents**:

- **Quick Estimate / Pricing Calculator:** Replaced with a non-pricing **"Start a Scope Review"** selector that routes directly to `/request-proposal/?service=...` (no fake quotes or automated pricing).
- **Client Portal Link:** Removed; replaced with the real `/request-service/` (**Existing Customer Service**) route.
- **Fake Downloadable PDFs (`Licensing & Insurance PDF`, `Service Overview PDF`, `Company Profile PDF`):** Replaced with real existing pages (`/credentials/`, `/about/`, `/service-area/`) alongside the real ungated `/credentials/capabilities.pdf`.
- **Unverified Metrics (`35+ Years of Experience`, `Guaranteed Response Time`):** Replaced with factual `Founded in 1989` and `Clear Written Scopes` / `Verified Licensing`.
- **Fabricated Projects & Testimonials:** The **Recent Projects** section renders approved public projects **only** when published records exist in the database; otherwise it shows a truthful verification notice linking to `/credentials/` and `/projects/`.

---

## 3. Missing / Client Approval Required

1. **Real Commercial Building & Property Photography:** Currently using generic AI-generated Southwest architectural visuals (`/assets/hero-building.jpg`, `/assets/prop-industrial.jpg`, `/assets/prop-retail.jpg`, `/assets/prop-office.jpg`, `/assets/prop-portfolio.jpg`), clearly labeled as generic architectural views—not completed client projects—until client-approved photography is uploaded.
2. **Full Office Street ZIP Code:** Address reference currently displays `2105 S Hardy Dr., Suite 17, Tempe, AZ` pending client confirmation of full ZIP.
3. **Final Mission & Vision Statement Wording (`/about/`):** Marked pending client approval.
4. **Approved Case Studies (`/projects/`):** Ready to publish via Admin Dashboard once client naming and photography rights are recorded.
