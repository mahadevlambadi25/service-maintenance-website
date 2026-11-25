import { fileURLToPath } from 'node:url';
import { ENV, ROLES } from '../config.js';
import { generateUuid, hashPassword } from '../lib/crypto.js';
import { getDb } from './database.js';

// Fixed deterministic Base32 secrets for local/staging QA test accounts (replace in production via Admin -> Users)
export const DEMO_USERS = [
  {
    user_id: 'usr-admin-01',
    email: 'admin@smiaz.local',
    full_name: 'Elena Vance (Platform Admin)',
    role: ROLES.PLATFORM_ADMIN,
    totp_secret: 'JBSWY3DPEHPK3PXP',
  },
  {
    user_id: 'usr-editor-01',
    email: 'editor@smiaz.local',
    full_name: 'Marcus Chen (Content Editor)',
    role: ROLES.CONTENT_EDITOR,
    totp_secret: 'KRSXG5CTMVRXEZLU',
  },
  {
    user_id: 'usr-publisher-01',
    email: 'publisher@smiaz.local',
    full_name: 'Michael Phillips (Approver & Publisher)',
    role: ROLES.APPROVER_PUBLISHER,
    totp_secret: 'MFRGGZDFMZTWQ2LK',
  },
  {
    user_id: 'usr-hiring-owner-01',
    email: 'hiring@smiaz.local',
    full_name: 'Sarah Jenkins (Hiring Owner)',
    role: ROLES.HIRING_OWNER,
    totp_secret: 'NBSWY3DPFQQHO33N',
  },
  {
    user_id: 'usr-hiring-reviewer-01',
    email: 'reviewer@smiaz.local',
    full_name: 'David Morales (Hiring Reviewer)',
    role: ROLES.HIRING_REVIEWER,
    totp_secret: 'ONSWG4TFOQQG64RA',
  },
  {
    user_id: 'usr-contributor-01',
    email: 'projects@smiaz.local',
    full_name: 'Carlos Reyes (Project Contributor)',
    role: ROLES.PROJECT_CONTRIBUTOR,
    totp_secret: 'ORSXG5DJNZTQ64RA',
  },
  {
    user_id: 'usr-analyst-01',
    email: 'analyst@smiaz.local',
    full_name: 'Priya Nair (Analyst)',
    role: ROLES.ANALYST,
    totp_secret: 'PBSWY3DPEB3W64RA',
  },
];

const SEED_PAGES = [
  {
    page_id: 'pg-home',
    slug: '/',
    template: 'home',
    title: 'Commercial Property Maintenance, Day Porters & Tenant Improvements | Service Maintenance',
    meta_title: 'Commercial Property Maintenance in Greater Phoenix | Service Maintenance',
    meta_description:
      'Day porter services, commercial building repairs, and tenant improvements for commercial properties across Greater Phoenix. Roots dating to 1989.',
    hero_headline: 'Commercial maintenance. Carefully managed.',
    hero_summary:
      'Day porter services, building repairs, and tenant improvements for commercial properties across Greater Phoenix.',
    cta_label: 'Request a proposal',
    cta_route: '/request-proposal/',
    service_family: null,
    owner_name: 'Ravi K. Swamy / COO',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Service Maintenance helps commercial owners, property managers, and facilities teams care for their properties through recurring services, maintenance and repairs, and tenant improvements. Our delivery model pairs accountable in-house personnel with coordinated specialty subcontractors across Greater Phoenix.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-services',
    slug: '/services/',
    template: 'service_overview',
    title: 'Commercial Property Services Overview | Service Maintenance',
    meta_title: 'Commercial Property Services in Greater Phoenix | Service Maintenance',
    meta_description:
      'Explore our three service pillars: recurring property care, commercial maintenance and repairs, and tenant improvements and make-ready.',
    hero_headline: 'Three service pillars for commercial properties across Greater Phoenix',
    hero_summary:
      'From scheduled day porter programs and routine building repairs to occupied-space tenant improvements and move-out make-ready.',
    cta_label: 'Request a proposal',
    cta_route: '/request-proposal/',
    service_family: null,
    owner_name: 'Operations Lead',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Every property requires a dependable entry point—whether that is a recurring weekly porter schedule, a multi-task facility repair list, or a coordinated suite turnover. We separate self-performed scopes from coordinated specialty trades and confirm every scope boundary in writing before work begins.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-commercial-maintenance',
    slug: '/services/commercial-maintenance/',
    template: 'service',
    title: 'Commercial Maintenance & Repairs',
    meta_title: 'Commercial Maintenance & Repairs in Phoenix | Service Maintenance',
    meta_description:
      'Interior and exterior commercial building repairs, drywall, doors and hardware, lighting, plumbing coordination, concrete, and suite cleanup across Greater Phoenix.',
    hero_headline: 'Commercial maintenance and repairs with clear scope coordination',
    hero_summary:
      'Reliable repair execution for small single-item work orders and multi-trade facility punch lists across occupied commercial properties.',
    cta_label: 'Tell us what needs attention',
    cta_route: '/request-proposal/?service=commercial-maintenance',
    service_family: 'commercial-maintenance',
    owner_name: 'COO / Service Lead',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Built for Both Routine Small Repairs and Multi-Task Facility Lists</h2>
      <p>Commercial facilities rarely fail neatly along single-trade lines. A damaged back-of-house door, ceiling tile staining, dock-side drywall impact, and exterior walkway spalling often need to be scoped together around tenant operating hours and delivery schedules. Service Maintenance manages both targeted small repairs and multi-item property punch lists without forcing buyers through an automated estimating questionnaire.</p>
      <h2>How We Scope and Coordinate Around Operating Sites</h2>
      <p>Before mobilizing, our team reviews photographs or conducts an on-site walk to document access requirements, occupied-space protection, working-hour constraints, and whether tasks are performed by our in-house technicians or coordinated with a licensed specialty subcontractor. You receive a clear written scope and a single accountable point of contact from review through closeout.</p>
      <h2>Important Scope Boundaries</h2>
      <p>Routine maintenance and minor troubleshooting are kept distinct from full HVAC system engineering, structural rack engineering, or regulated hazardous-material remediation. Where a building need requires a licensed specialist or formal permitting, we identify that requirement transparently during scoping rather than making blanket "we do everything" claims.</p>
    `,
    scopes: [
      { name: 'Interior repairs', detail: 'Drywall patching, texture matching, painting, acoustic ceiling tile and grid replacement, interior doors, hardware, fixtures, and minor installations.' },
      { name: 'Doors, hardware & glazing coordination', detail: 'Door closers, hinges, panic hardware, lockset adjustments, and coordinated glass or storefront specialty repairs.' },
      { name: 'Electrical & lighting maintenance', detail: 'Lamp and ballast replacements, switches/outlets, troubleshooting, and coordinated licensed electrical work where required.' },
      { name: 'Plumbing maintenance', detail: 'Fixtures, faucet/valve replacements, toilet repairs, leaks, and coordinated licensed plumbing for permitted or complex scopes.' },
      { name: 'Flooring & finishes', detail: 'Cove base, VCT/carpet tile patching, concrete floor patching, and coordinated epoxy or full-flooring installations.' },
      { name: 'Concrete, welding & site repairs', detail: 'Walkway repairs, bollard installation/repair, block wall repairs, approved facility welding, and final/suite cleanup.' },
    ],
    faqs: [
      { q: 'Is there a minimum project size for commercial maintenance inquiries?', a: 'No. Ordinary commercial repair requests and small multi-task property lists are welcome alongside larger projects.' },
      { q: 'Can you work after hours or around tenant deliveries?', a: 'Yes. Access windows, occupied common areas, and delivery docks are planned into the agreed scope before work starts.' },
      { q: 'Are all trades self-performed in-house?', a: 'No. Our model pairs in-house technicians with vetted specialty subcontractors for licensed or specialized scopes, coordinated under one relationship.' },
    ],
  },
  {
    page_id: 'pg-day-porter',
    slug: '/services/day-porter/',
    template: 'service',
    title: 'Day Porter Services',
    meta_title: 'Commercial Day Porter Services in Phoenix | Service Maintenance',
    meta_description:
      'Scheduled daytime porter programs for Greater Phoenix retail centers, office buildings, and business parks with documented task plans and supervision.',
    hero_headline: 'Day porter programs designed around your property’s daily rhythm',
    hero_summary:
      'Consistent daytime common-area care, litter and receptacle service, walkway presentation, and prompt issue reporting for occupied commercial properties.',
    cta_label: 'Discuss your property care needs',
    cta_route: '/request-proposal/?service=day-porter',
    service_family: 'day-porter',
    owner_name: 'Day Porter Manager / COO',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Accountable Daytime Presence Since 1989</h2>
      <p>Our roots date to 1989 when Service Maintenance began providing day porter services in Greater Phoenix. Decades of supporting retail centers, multi-tenant offices, and industrial parks have shown that reliable porter care depends on clear site task plans, dependable supervision, and honest communication when maintenance issues appear.</p>
      <h2>Day Porter Services vs. Suite Cleaning and Janitorial Contracts</h2>
      <p>Daytime porter service focuses on visible exterior and shared-property presentation during operating hours—not overnight janitorial contracts or hospital-grade disinfection. While our teams also perform in-house final and suite cleaning for turnovers, each porter agreement clearly defines which tasks are included, which supplies are provided, and what sits outside the agreed schedule.</p>
      <h2>Program Scoping, Supervision & Escalation</h2>
      <p>Every property receives a tailored task list covering visit frequency, route priorities, dumpster enclosures, walkway spill response, and common-area touchpoints. When a porter spots damage, vandalism, or a repair need beyond routine upkeep, the observation is documented and routed to your property manager so repairs can be authorized before small issues become costly liabilities.</p>
    `,
    scopes: [
      { name: 'Site task plans & frequency', detail: 'Scheduled routes calibrated to foot traffic, retail peak hours, or multi-building business park needs.' },
      { name: 'Litter & receptacle care', detail: 'Parking field, landscape bed, and sidewalk policing, trash receptacle emptying, and liner replacement.' },
      { name: 'Common-area & walkway presentation', detail: 'Entry glass spot-cleaning, patio/breezeway upkeep, cobweb removal, and prompt attention to spills or debris.' },
      { name: 'Dumpster enclosure attention', detail: 'Enclosure sweeping, loose debris clearing, and reporting of illegal dumping or haul-away needs.' },
      { name: 'Supplies & minor reporting', detail: 'Consumables restocking where included in the contract and structured reporting of facility defects.' },
    ],
    faqs: [
      { q: 'How is a day porter program scoped?', a: 'We walk the property with the manager to map building entrances, enclosures, peak tenant hours, and required visit frequency before issuing a clear task schedule.' },
      { q: 'Do day porters handle major building repairs?', a: 'Porters focus on scheduled presentation and routine upkeep; when a repair is discovered, it is escalated for approval through our maintenance team.' },
    ],
  },
  {
    page_id: 'pg-recurring-property-care',
    slug: '/services/recurring-property-care/',
    template: 'service',
    title: 'Recurring Property Care',
    meta_title: 'Recurring Commercial Property Care | Service Maintenance',
    meta_description:
      'Scheduled exterior and common-area upkeep across Greater Phoenix including day porters, pressure washing, parking lot sweeping, and roof cleaning observations.',
    hero_headline: 'Scheduled property care built for predictable long-term upkeep',
    hero_summary:
      'Coordinated recurring programs combining in-house porter care, scheduled exterior cleaning, and preventative visual observations.',
    cta_label: 'Request a property assessment',
    cta_route: '/request-proposal/?service=recurring-property-care',
    service_family: 'recurring-property-care',
    owner_name: 'COO / Operations',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Continuity Across Recurring Exterior and Common-Area Needs</h2>
      <p>Keeping a commercial asset presentable takes more than reacting after a tenant complaint. Our recurring property care pillar coordinates routine daytime porter visits with periodic exterior maintenance—reducing vendor fragmentation for property managers overseeing retail centers, industrial parks, and commercial offices.</p>
      <h2>Transparent In-House and Coordinated Scope Delivery</h2>
      <p>Rather than offering generic Bronze/Silver/Gold tiers with hidden exclusions, we scope recurring programs to the actual surfaces, access rules, water/runoff constraints, and seasonal conditions of each site. Where specialized equipment or licensed trades are required—such as height-restricted window washing or landscaping/pest specialists—we coordinate approved partners under clear boundaries.</p>
    `,
    scopes: [
      { name: 'Day porter programs', detail: 'Scheduled in-house daytime policing, common areas, and property presentation.' },
      { name: 'Pressure washing', detail: 'Sidewalks, entries, dumpster pads, and approved hardscapes with surface protection and water/runoff planning.' },
      { name: 'Parking lot sweeping', detail: 'Coordinated sweeping schedules aligned with tenant operating hours and debris handling.' },
      { name: 'Roof inspection & cleaning', detail: 'Scheduled visual condition observations, debris and scupper/drainage clearing—clearly distinct from roof warranties or engineering certification.' },
      { name: 'Coordinated exterior specialists', detail: 'Window washing (within verified height/access limits) and secondary recurring landscaping/pest coordination where approved.' },
    ],
    faqs: [
      { q: 'Does roof cleaning include a roof warranty or structural certification?', a: 'No. Scheduled roof cleaning covers debris removal, drainage attention, and visual observations for owner review—not engineering certification or roof warranties.' },
      { q: 'Can multiple recurring services be scheduled on one property assessment?', a: 'Yes. We assess porter frequency, pressure washing, sweeping, and seasonal debris clearing together.' },
    ],
  },
  {
    page_id: 'pg-building-engineer',
    slug: '/services/building-engineer/',
    template: 'service',
    title: 'Building Engineer Services',
    meta_title: 'Commercial Building Operations Support | Service Maintenance',
    meta_description:
      'Scheduled on-site building operations support, routine checks, and minor maintenance coordination for Greater Phoenix commercial properties.',
    hero_headline: 'Scheduled on-site building operations support',
    hero_summary:
      'Routine facility checks, minor preventative maintenance within agreed boundaries, and vendor escorting/coordination—distinct from licensed design engineering.',
    cta_label: 'Discuss building support',
    cta_route: '/request-proposal/?service=building-engineer',
    service_family: 'building-engineer',
    owner_name: 'COO',
    editorial_state: 'Draft',
    activation_state: 'Unpublished',
    is_conditional: 1, // Hidden from public nav/sitemap until operations approves current scope!
    indexable: 1,
    body_html: `
      <h2>Practical On-Site Operations Support</h2>
      <p>In commercial real estate, "building engineer" describes scheduled hands-on building operations support—not licensed structural, mechanical, or electrical design engineering. Our operations staff perform routine walkthroughs, filter checks, minor hardware/fixture adjustments, and vendor coordination within clearly documented boundaries.</p>
    `,
    scopes: [
      { name: 'Scheduled site rounds', detail: 'Routine visual checks of mechanical rooms, common corridors, lighting, and life-safety access clearances.' },
      { name: 'Minor preventative upkeep', detail: 'Routine filter changes, belt checks where scoped, door hardware adjustments, and logbook updates.' },
      { name: 'Issue escalation & vendor coordination', detail: 'Meeting specialty HVAC, elevator, or fire-system vendors on site and tracking follow-up items.' },
    ],
    faqs: [
      { q: 'Does this service include stamped engineering design?', a: 'No. The title refers to commercial building operations support and routine hands-on facility care, not licensed professional engineering.' },
    ],
  },
  {
    page_id: 'pg-tenant-improvements',
    slug: '/services/tenant-improvements/',
    template: 'service',
    title: 'Tenant Improvements & Renovations',
    meta_title: 'Commercial Tenant Improvements in Greater Phoenix | Service Maintenance',
    meta_description:
      'Commercial tenant improvements, interior alterations, trade sequencing, permit/design coordination, and occupied-building renovations across Greater Phoenix.',
    hero_headline: 'Tenant improvements planned for accountability and clean turnover',
    hero_summary:
      'Commercial interior alterations, suite build-outs, and phased renovations delivered with documented scope planning, change control, and closeout.',
    cta_label: 'Discuss your improvement project',
    cta_route: '/request-proposal/?service=tenant-improvements',
    service_family: 'tenant-improvements',
    owner_name: 'TI Project Management',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Scope Clarity Before Mobilization</h2>
      <p>Successful tenant improvements depend on aligning owner expectations, landlord rules, existing building conditions, and specialty trade sequencing early. Under Promptitude Inc.’s ownership since 2020 and building on general contracting experience dating back to 2006, Service Maintenance delivers commercial interior alterations across office, retail, and warehouse spaces.</p>
      <h2>How We Manage Assumptions, Permits, and Occupied Buildings</h2>
      <p>Every TI project starts by confirming site assumptions and identifying exclusions explicitly—including whether architectural/engineering design, municipal permitting, hazardous-material evaluation, or owner-supplied materials apply to your contract. We do not imply in-house architectural or engineering licensure; instead, we coordinate qualified design professionals and specialty mechanical, electrical, plumbing, and fire trades as required by the project.</p>
      <h2>Change Control and Clean Closeout</h2>
      <p>Occupied commercial buildings require careful attention to noise windows, dust containment, loading access, and shared corridors. We document schedule milestones, secure written approval for scope changes, and complete final cleaning and punch-list verification prior to turnover.</p>
    `,
    scopes: [
      { name: 'Scope development & site assessment', detail: 'Walkthrough verification of existing partitions, MEP tie-ins, ceiling heights, and landlord construction rules.' },
      { name: 'Selective demolition & framing', detail: 'Controlled interior demo, metal stud framing, acoustic insulation, drywall, and rated partition coordination where specified.' },
      { name: 'Ceilings, finishes & millwork', detail: 'Acoustical grids, doors/frames/hardware, flooring, paint, wall protection, and coordinated casework/millwork.' },
      { name: 'Trade & permit coordination', detail: 'Sequencing electrical, plumbing, HVAC, low-voltage, and permitting/inspection milestones with required professionals.' },
      { name: 'Final cleaning & punch closeout', detail: 'In-house final suite cleaning, punch-list walk, and documented closeout package.' },
    ],
    faqs: [
      { q: 'Can I attach an RFP or preliminary floor plan with my inquiry?', a: 'Yes. Our Request a Proposal form includes a dedicated TI/RFP upload path for PDFs, drawings, or photographs (up to 25 MB total).' },
      { q: 'Do you provide in-house architectural stamping?', a: 'No. Where stamped drawings or engineering are required, we coordinate with licensed architects and engineers under the agreed project structure.' },
    ],
  },
  {
    page_id: 'pg-tenant-move-outs',
    slug: '/services/tenant-move-outs/',
    template: 'service',
    title: 'Tenant Move-Outs & Make-Ready',
    meta_title: 'Commercial Tenant Move-Outs & Make-Ready | Service Maintenance',
    meta_description:
      'Suite turnover, selective removal, white-shell/put-back work, patch and paint, final suite cleaning, and haul-away for Greater Phoenix properties.',
    hero_headline: 'Efficient tenant move-outs and lease-return make-ready',
    hero_summary:
      'Coordinated suite restoration, selective demolition, repairs, final cleaning, and haul-away to prepare commercial spaces for the next occupant.',
    cta_label: 'Share your turnover scope',
    cta_route: '/request-proposal/?service=tenant-move-outs',
    service_family: 'tenant-move-outs',
    owner_name: 'COO / TI Team',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Bridging Lease Return and Next-Tenant Readiness</h2>
      <p>When a commercial tenant vacates, landlords and property managers need rapid, accurate restoration aligned with the owner’s white-shell or put-back specifications. Service Maintenance coordinates selective removal, drywall and ceiling repair, lighting restoration, painting, debris haul-away, and in-house final suite cleaning under one clear scope.</p>
      <h2>Practical Scope Boundaries</h2>
      <p>We work directly from your documented scope, walkthrough notes, or owner turnover checklist. Service Maintenance does not provide legal interpretations of lease agreements or guarantee blanket code compliance outside an explicitly defined and permitted scope.</p>
    `,
    scopes: [
      { name: 'Selective removal & haul-away', detail: 'Removal of abandoned tenant fixtures, non-structural partitions, cabling (where scoped), and debris disposal.' },
      { name: 'White-shell & put-back work', detail: 'Wall patching, priming/paint, ceiling grid and tile restoration, and lighting/door hardware return to working order.' },
      { name: 'Final suite cleaning', detail: 'In-house post-work suite cleaning covering floors, glass, restrooms, and back-of-house areas ready for leasing tours.' },
    ],
    faqs: [
      { q: 'Do you handle furniture liquidation or regulated hazardous waste?', a: 'General commercial debris haul-away and suite cleanout are supported within agreed scopes; regulated remediation requires specialized environmental contractors.' },
    ],
  },
  {
    page_id: 'pg-warehouse-repairs',
    slug: '/services/warehouse-repairs/',
    template: 'service',
    title: 'Warehouse & Industrial Repairs',
    meta_title: 'Warehouse Scrim, Insulation & Industrial Facility Repairs | Service Maintenance',
    meta_description:
      'Warehouse scrim and insulation repair, dock concrete, bollards, industrial doors, and high-access facility repairs across Greater Phoenix.',
    hero_headline: 'Warehouse and industrial repairs scoped around active operations',
    hero_summary:
      'Scrim and roof-deck insulation repair, concrete and bollard protection, welding, doors, and facility upkeep coordinated around lifts, docks, and shift hours.',
    cta_label: 'Request a warehouse site discussion',
    cta_route: '/request-proposal/?service=warehouse-repairs',
    service_family: 'warehouse-repairs',
    owner_name: 'Industrial / Maintenance Lead',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>High-Access and Active-Dock Execution</h2>
      <p>Industrial and distribution facilities operate on tight dock schedules, narrow aisle clearances, and strict safety rules. Our teams scope warehouse repairs—including damaged ceiling scrim and insulation replacement, dock-door framing, slab/apron concrete repairs, protective bollards, and approved welding—with explicit planning for lift access, staging zones, and shift traffic.</p>
      <h2>Equipment & Specialist Boundaries</h2>
      <p>Scissor lifts, boom lifts, and specialty access equipment are arranged as needed for the project; we do not imply ownership of every piece of specialized machinery. Structural pallet-rack engineering, fire-suppression systems, and process-water lines require clearly bounded scopes and licensed specialists.</p>
    `,
    scopes: [
      { name: 'Scrim & insulation repair/replacement', detail: 'Repairing torn vinyl scrim, sagging batts, and compromised roof-deck insulation panels at bay height.' },
      { name: 'Concrete, aprons & protective bollards', detail: 'Slab spall repairs, trip-hazard grinding, dock apron patching, and steel bollard installation or straightening.' },
      { name: 'Doors, walls & facility welding', detail: 'Demising wall repairs, man-doors/hardware, dock-area protection, and approved fabrication/welding tasks.' },
      { name: 'Work-zone & safety coordination', detail: 'Barricading active forklift lanes, scheduling off-shift lift access, and maintaining required PPE standards.' },
    ],
    faqs: [
      { q: 'Can you work in an active 24-hour distribution warehouse?', a: 'Yes, provided work-zone isolation, aisle closures, and shift timing are coordinated in advance with your facility manager.' },
      { q: 'Do you certify structural pallet rack modifications?', a: 'No. Rack modifications or structural alterations require appropriate engineering review and specialist certification.' },
    ],
  },
  {
    page_id: 'pg-exterior-site-maintenance',
    slug: '/services/exterior-site-maintenance/',
    template: 'service',
    title: 'Exterior & Site Maintenance',
    meta_title: 'Commercial Exterior & Site Maintenance in Phoenix | Service Maintenance',
    meta_description:
      'Carport and awning repairs, stucco/masonry, concrete walkways, gates and fencing, exterior lighting, graffiti removal, and storm drain cleaning.',
    hero_headline: 'Exterior and site repairs protecting curb appeal and access',
    hero_summary:
      'Practical exterior upkeep across Greater Phoenix—concrete, stucco, carports, gates, exterior lighting, graffiti removal, and storm drainage cleaning.',
    cta_label: 'Tell us about your property',
    cta_route: '/request-proposal/?service=exterior-site-maintenance',
    service_family: 'exterior-site-maintenance',
    owner_name: 'COO / Exterior Coordinator',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Organized Around Real Site Conditions</h2>
      <p>Desert sun, monsoon storms, delivery trucks, and daily tenant traffic wear down commercial exteriors quickly. Service Maintenance groups exterior services by property issue—whether it is structural appearance, safety around walkways and gates, or pre-monsoon drainage clearing—identifying in-house work and coordinated specialty trades upfront.</p>
    `,
    scopes: [
      { name: 'Stucco, masonry & block walls', detail: 'Impact repair, crack patching, color-matched exterior painting, and perimeter block wall maintenance.' },
      { name: 'Carports, awnings & signage', detail: 'Post repairs, sheet-metal trim, fascia fixes, and non-illuminated monument/building sign mounting.' },
      { name: 'Concrete, asphalt & fences/gates', detail: 'Sidewalk repairs, curb stops, weld-gate hinge repairs, latches, and perimeter fencing upkeep.' },
      { name: 'Drainage, pressure washing & graffiti removal', detail: 'Downspout repair, storm drain/drywell debris clearing, surface washing, and fast graffiti cover/removal.' },
    ],
    faqs: [
      { q: 'Do you perform fire watch services?', a: 'Fire watch is a separate, conditional operational service with distinct requirements and never replaces functioning fire protection systems or authority approval.' },
    ],
  },
  {
    page_id: 'pg-properties',
    slug: '/properties/',
    template: 'property_overview',
    title: 'Commercial Properties We Serve',
    meta_title: 'Commercial Properties Served in Greater Phoenix | Service Maintenance',
    meta_description:
      'Tailored maintenance, day porter, and tenant improvement support for industrial warehouses, retail centers, commercial offices, and multi-site portfolios.',
    hero_headline: 'Services tailored to how your commercial property operates',
    hero_summary:
      'Primary experience across industrial and warehouse facilities, retail centers, commercial office buildings, and managed property portfolios.',
    cta_label: 'Request a proposal',
    cta_route: '/request-proposal/',
    service_family: null,
    owner_name: 'Business Sponsor / COO',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Different commercial properties carry different risks, hours, and tenant expectations. Explore how we structure scopes for industrial facilities, retail centers, and multi-tenant office buildings across Greater Phoenix.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-prop-industrial',
    slug: '/properties/industrial-warehouses/',
    template: 'property',
    title: 'Industrial & Warehouse Facilities',
    meta_title: 'Industrial & Warehouse Property Maintenance | Service Maintenance',
    meta_description:
      'Warehouse scrim, insulation, dock concrete, bollards, and make-ready support tailored to active distribution facilities in Greater Phoenix.',
    hero_headline: 'Industrial and warehouse care built around dock schedules',
    hero_summary:
      'Protecting active aisles, high-bay insulation, loading docks, and industrial turnover timelines without unrealistic zero-disruption promises.',
    cta_label: 'Request a warehouse site discussion',
    cta_route: '/request-proposal/?service=warehouse-repairs',
    service_family: 'warehouse-repairs',
    owner_name: 'Industrial Lead',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Distribution centers, flex industrial parks, and logistics warehouses demand clear work-zone planning, lift coordination, and reliable closeout. From ceiling scrim patching and bollard replacement to full warehouse office make-ready, we align scopes with facility safety and dock access.</p>',
    scopes: [
      { name: 'Active-bay scrim & insulation', detail: 'High-reach repair scheduled around forklift traffic and pallet bays.' },
      { name: 'Dock & yard upkeep', detail: 'Concrete spalls, bollards, man-doors, striping coordination, and perimeter gate repairs.' },
      { name: 'Industrial office build-outs & turnovers', detail: 'Warehouse office TI, restroom upgrades, and lease-end white-shell restoration.' },
    ],
    faqs: [],
  },
  {
    page_id: 'pg-prop-retail',
    slug: '/properties/retail-centers/',
    template: 'property',
    title: 'Retail Centers',
    meta_title: 'Retail Center Day Porter & Maintenance Services | Service Maintenance',
    meta_description:
      'Day porter programs, pressure washing, lighting, stucco, and suite turnovers for Greater Phoenix retail shopping centers.',
    hero_headline: 'Keeping customer-facing retail centers clean, safe, and maintained',
    hero_summary:
      'Daytime porter visibility, walkway washing, exterior repairs, and smooth inline suite make-ready between tenants.',
    cta_label: 'Discuss your retail property',
    cta_route: '/request-proposal/?service=day-porter',
    service_family: 'day-porter',
    owner_name: 'Day Porter Manager',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Retail centers succeed on first impressions and unobstructed customer walkways. Our day porters maintain parking fields, patios, and enclosures during shopping hours while our maintenance and TI teams handle storefront/door hardware repairs, pressure washing, graffiti removal, and vacant suite turnarounds.</p>',
    scopes: [
      { name: 'Daytime porter routes', detail: 'Common-area policing, receptacles, spill cleanup, and vendor observation reporting.' },
      { name: 'Exterior & walkway care', detail: 'Pressure washing, canopy/stucco repairs, bollard painting, and exterior lighting maintenance.' },
      { name: 'Inline suite turnovers', detail: 'Make-ready demo, drywall, ceiling grids, and final suite cleaning for incoming tenants.' },
    ],
    faqs: [],
  },
  {
    page_id: 'pg-prop-office',
    slug: '/properties/commercial-offices/',
    template: 'property',
    title: 'Commercial Offices & Multi-Tenant Buildings',
    meta_title: 'Commercial Office Maintenance & Tenant Improvements | Service Maintenance',
    meta_description:
      'Occupied-building repairs, common-area upkeep, and commercial suite renovations for Phoenix office properties.',
    hero_headline: 'Quiet, coordinated care for occupied commercial office buildings',
    hero_summary:
      'Protecting lobbies, shared corridors, and active tenant suites with scheduled maintenance, daytime support, and planned tenant improvements.',
    cta_label: 'Request a proposal',
    cta_route: '/request-proposal/?service=tenant-improvements',
    service_family: 'tenant-improvements',
    owner_name: 'TI / Maintenance Lead',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Multi-tenant office buildings require clean staging, after-hours coordination for noisy work, and careful protection of lobbies and elevators. We support office managers with recurring common-area upkeep, rapid suite repair lists, and complete office tenant improvements.</p>',
    scopes: [
      { name: 'Common-area & corridor upkeep', detail: 'Doors/closers, suite signage mounting, restroom fixtures, ceiling tiles, and wall finishes.' },
      { name: 'Suite renovations & move-outs', detail: 'Partition additions, conference room build-outs, flooring coordination, and turnover cleaning.' },
    ],
    faqs: [],
  },
  {
    page_id: 'pg-property-managers',
    slug: '/property-managers/',
    template: 'buyer_solution',
    title: 'For Commercial Property Managers',
    meta_title: 'Partnering With Commercial Property Managers | Service Maintenance',
    meta_description:
      'Single-relationship support for multi-site commercial property managers in Greater Phoenix across recurring porters, repairs, and tenant improvements.',
    hero_headline: 'One accountable service relationship across your property lifecycle',
    hero_summary:
      'Supporting property and asset managers overseeing multiple Greater Phoenix properties—from daily porter schedules to repair work orders and suite turnovers.',
    cta_label: 'Discuss your portfolio needs',
    cta_route: '/request-proposal/?service=recurring-property-care',
    service_family: 'recurring-property-care',
    owner_name: 'Business Sponsor / COO',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Property managers juggle recurring vendor schedules, unexpected tenant repair requests, and capital turnover projects across multiple addresses. Instead of coordinating separate contractors for every stage, Service Maintenance connects recurring care, repairs, and tenant improvements through clear communication and documented scope approvals. When submitting an inquiry for multiple properties, tell us which locations are involved and who approves work so we can route your request cleanly.</p>',
    scopes: [
      { name: 'Multi-property inquiry routing', detail: 'Specify multiple sites, approval contacts, and property types in a single proposal request.' },
      { name: 'Continuity from upkeep to TI', detail: 'Issues spotted during recurring visits can be scoped into repairs or turnover projects without starting over.' },
      { name: 'Procurement-ready documentation', detail: 'Access verified Arizona ROC numbers, legal entity details, and insurance documentation on request.' },
    ],
    faqs: [],
  },
  {
    page_id: 'pg-about',
    slug: '/about/',
    template: 'company',
    title: 'About Service Maintenance',
    meta_title: 'About Service Maintenance (Promptitude Inc.) | Greater Phoenix',
    meta_description:
      'Learn about Service Maintenance’s roots dating to 1989, leadership transition to Promptitude Inc. in 2020, and our five core operating values.',
    hero_headline: 'Our roots date to 1989 across Greater Phoenix',
    hero_summary:
      'Built on decades of commercial property service—combining dependable in-house care with accountable specialty coordination.',
    cta_label: 'Request a proposal',
    cta_route: '/request-proposal/',
    service_family: null,
    owner_name: 'Ravi K. Swamy',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Service Maintenance is the trading name of Promptitude Inc., serving commercial properties across Greater Phoenix through recurring property care, maintenance and repairs, and tenant improvements.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-credentials',
    slug: '/credentials/',
    template: 'procurement',
    title: 'Credentials, Licensing & Procurement Information',
    meta_title: 'Licenses, Legal Identity & Capabilities | Service Maintenance',
    meta_description:
      'Procurement reference for Promptitude Inc. dba Service Maintenance: Arizona ROC numbers 334827, 328349, 328350, insurance statement, and downloadable Capabilities PDF.',
    hero_headline: 'Verified credentials and procurement documentation',
    hero_summary:
      'Clear legal identity, Arizona Registrar of Contractors numbers, insurance confirmation process, and an ungated Capabilities Statement.',
    cta_label: 'Request procurement documentation',
    cta_route: '/request-proposal/?service=procurement',
    service_family: 'procurement',
    owner_name: 'Operations Administration',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Vendor onboarding and procurement reviewers can verify our legal identity, review active Arizona contractor classifications, download our Capabilities Statement without completing a lead gate, or request current insurance certificates through our monitored operations channel.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-service-area',
    slug: '/service-area/',
    template: 'geography',
    title: 'Greater Phoenix Service Area',
    meta_title: 'Greater Phoenix Commercial Service Area | Service Maintenance',
    meta_description:
      'Commercial maintenance, day porter, and tenant improvement coverage across Greater Phoenix including Phoenix, Tempe, Scottsdale, Mesa, Chandler, Gilbert, Glendale, Peoria, and Goodyear.',
    hero_headline: 'Serving commercial properties across Greater Phoenix',
    hero_summary:
      'Dispatch and project coordination for commercial properties throughout the Greater Phoenix metro area—and for out-of-state owners managing Arizona assets.',
    cta_label: 'Check coverage for your property',
    cta_route: '/request-proposal/',
    service_family: null,
    owner_name: 'Operations Lead',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Service Maintenance operates across Greater Phoenix. Whether your facilities team is based locally in the Valley or your ownership group manages a Phoenix portfolio from outside Arizona, inquiries are routed based on where the commercial property is located.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-contact',
    slug: '/contact/',
    template: 'contact',
    title: 'Contact Service Maintenance',
    meta_title: 'Contact Service Maintenance | Greater Phoenix Commercial Services',
    meta_description:
      'Reach Service Maintenance by phone at (480) 423-9196, request a new commercial proposal, submit an existing-client service request, or view vendor/careers contacts.',
    hero_headline: 'Connect with our Greater Phoenix team',
    hero_summary:
      'Choose the right path for new commercial proposals, existing-client service requests, procurement onboarding, or careers.',
    cta_label: 'Request a proposal',
    cta_route: '/request-proposal/',
    service_family: null,
    owner_name: 'Operations Administration',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html:
      '<p>Call our office during America/Phoenix business hours or use the dedicated online routes below so your request reaches the right operational owner immediately.</p>',
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-privacy',
    slug: '/privacy/',
    template: 'policy',
    title: 'Privacy Policy & Cookie Choices',
    meta_title: 'Privacy Policy & Data Handling | Service Maintenance',
    meta_description:
      'How Promptitude Inc. dba Service Maintenance handles commercial inquiry data, applicant records, consent preferences, and privacy requests.',
    hero_headline: 'Privacy Policy and Data Handling',
    hero_summary:
      'Transparent disclosure of how inquiry records, protected employment applications, and optional analytics consent preferences are handled.',
    cta_label: 'Manage cookie preferences',
    cta_route: '#consent-settings',
    service_family: null,
    owner_name: 'Privacy / Administration',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>1. Who Operates This Website</h2>
      <p>This website is operated by Promptitude Inc., trading as Service Maintenance ("Company"). Privacy inquiries, access requests, corrections, or deletion requests may be sent to our monitored privacy contact listed below.</p>
      <h2>2. Commercial Inquiries & Existing-Client Requests</h2>
      <p>Information submitted through Request a Proposal or Request Service (including contact details, property location, scope description, and optional attachments) is stored durably and routed to our sales, estimating, or operations teams and Freshsales CRM so we can respond to your request. Submitting an inquiry does not enroll you in promotional marketing unless you separately check the optional marketing consent box.</p>
      <h2>3. Protected Employment Applications</h2>
      <p>Employment applications and resumes submitted through Careers are stored in a protected recruiting domain separate from sales CRM records and marketing analytics. Applicant files are never published in the public media library or used for advertising remarketing.</p>
      <h2>4. Cookies & Optional Analytics</h2>
      <p>By default, only strictly necessary session and security functionality runs before you make a cookie preference choice. Optional analytics events are stripped of names, emails, telephone numbers, free-text scopes, and filenames.</p>
    `,
    scopes: [],
    faqs: [],
  },
  {
    page_id: 'pg-accessibility',
    slug: '/accessibility/',
    template: 'policy',
    title: 'Accessibility Statement',
    meta_title: 'Website Accessibility Statement | Service Maintenance',
    meta_description:
      'Our commitment to WCAG 2.2 AA accessibility across public pages, forms, before/after media comparisons, and application workflows.',
    hero_headline: 'Website Accessibility',
    hero_summary:
      'Service Maintenance targets WCAG 2.2 Level AA across our public pages, inquiry forms, before/after comparisons, and careers application flow.',
    cta_label: 'Contact us about accessibility',
    cta_route: '/contact/',
    service_family: null,
    owner_name: 'Platform Administrator',
    editorial_state: 'Approved',
    activation_state: 'Live',
    is_conditional: 0,
    indexable: 1,
    body_html: `
      <h2>Accessibility Practices</h2>
      <p>We structure pages with semantic landmarks, keyboard-operable navigation, visible focus states, descriptive labels and error summaries, static before-and-after project views that never require dragging a slider, and full usability at 320px width and 200% browser zoom.</p>
      <h2>Feedback & Alternative Assistance</h2>
      <p>If you encounter any difficulty accessing information, submitting a proposal request, or applying for a position, please call our office during America/Phoenix business hours at (480) 423-9196 or reach us via our Contact page.</p>
    `,
    scopes: [],
    faqs: [],
  },
];

const SEED_CLAIMS = [
  {
    claim_id: 'clm-roots-1989',
    claim_type: 'fact',
    title: 'Company Founding & Ownership History',
    exact_text: 'Our roots date to 1989 (founded by Patrick Voita), original incorporation 1992, Greg Vandenberg joined 2006, Promptitude Inc. acquired June 29, 2020.',
    attribution: 'Owner-confirmed business context [C1]',
    evidence_source: 'Company corporate records',
    owner_name: 'Ravi K. Swamy',
    status: 'established company fact',
    allowed_placements_json: '["home","about","credentials"]',
  },
  {
    claim_id: 'clm-roc-licenses',
    claim_type: 'certification',
    title: 'Arizona ROC Numbers',
    exact_text: 'Arizona ROC numbers 334827, 328349, and 328350 (confirm current active status & classifications via AZ ROC before launch).',
    attribution: 'Company context & existing site [C1, W2]',
    evidence_source: 'Arizona Registrar of Contractors',
    owner_name: 'Operations Administration',
    status: 'evidence needed',
    allowed_placements_json: '["credentials","footer"]',
  },
  {
    claim_id: 'clm-insurance',
    claim_type: 'fact',
    title: 'Insurance Documentation Availability',
    exact_text: 'Insurance documentation available on request (general liability, umbrella, commercial auto, workers compensation).',
    attribution: 'Company context [C1]',
    evidence_source: 'Current Certificates of Insurance',
    owner_name: 'Operations Administration',
    status: 'proposed wording',
    allowed_placements_json: '["credentials","footer"]',
  },
  {
    claim_id: 'clm-turnover-withdrawn',
    claim_type: 'fact',
    title: 'Legacy Comparative Employee-Turnover Claim (Withdrawn)',
    exact_text: 'Legacy homepage comparative employee-turnover claim — withdrawn for lack of comparative evidence.',
    attribution: 'PRD Section 02.02',
    evidence_source: 'Legacy website audit',
    owner_name: 'Ravi K. Swamy',
    status: 'withdrawn',
    allowed_placements_json: '[]',
  },
];

const SEED_REDIRECTS = [
  { old_path: '/services', destination_path: '/services/', reason: 'PRD 23.01 normalize service overview trailing slash' },
  { old_path: '/building-engineering', destination_path: '/services/commercial-maintenance/', reason: 'PRD 23.01 preserve broad repair intent' },
  { old_path: '/day-porter-services', destination_path: '/services/day-porter/', reason: 'PRD 23.01 equivalent service' },
  { old_path: '/special-projects', destination_path: '/services/tenant-move-outs/', reason: 'PRD 23.01 preserve move-out/make-ready intent' },
  { old_path: '/tenant-improvements-1', destination_path: '/services/tenant-improvements/', reason: 'PRD 23.01 normalize TI route' },
  { old_path: '/contact-us', destination_path: '/contact/', reason: 'PRD 23.01 preserve clear company contact access' },
];

const SEED_ARTICLES = [
  {
    article_id: 'art-turnover-planning',
    slug: 'commercial-tenant-turnover-planning',
    title: 'Planning a Commercial Tenant Turnover Without Surprises',
    buyer_target: 'Owner / Commercial Property Manager',
    related_service: 'tenant-move-outs',
    summary: 'How to structure a lease-return walkthrough, separate put-back items from upgrades, and sequence cleaning before leasing tours.',
    body_html: '<p>Draft editorial article awaiting operations and publisher review prior to publication on Insights.</p>',
    sources_note: 'Internal operations walkthrough checklist',
    author_name: 'Marcus Chen',
    editorial_state: 'Draft',
    activation_state: 'Unpublished',
  },
  {
    article_id: 'art-day-porter-scope',
    slug: 'defining-a-day-porter-scope',
    title: 'How to Define a Clear Day Porter Scope for Retail and Office Centers',
    buyer_target: 'Commercial Property Manager',
    related_service: 'day-porter',
    summary: 'Setting realistic task schedules, enclosure priorities, and repair escalation paths for daytime property care.',
    body_html: '<p>Draft editorial article awaiting Day Porter Manager review prior to publication on Insights.</p>',
    sources_note: 'Day porter operations guidelines',
    author_name: 'Marcus Chen',
    editorial_state: 'Draft',
    activation_state: 'Unpublished',
  },
  {
    article_id: 'art-warehouse-inquiry',
    slug: 'preparing-a-warehouse-repair-inquiry',
    title: 'What Helps Speed Up a Warehouse Repair Scope Review',
    buyer_target: 'Facilities / Operations Manager',
    related_service: 'warehouse-repairs',
    summary: 'Key details to share up front—bay height, shift hours, aisle access, and photos—so scoping goes smoothly.',
    body_html: '<p>Draft editorial article awaiting Industrial Operations review prior to publication on Insights.</p>',
    sources_note: 'Industrial repair scoping checklist',
    author_name: 'Marcus Chen',
    editorial_state: 'Draft',
    activation_state: 'Unpublished',
  },
];

export async function seedDatabase(db = null) {
  if (!db) db = await getDb();
  const now = new Date().toISOString();

  // 1. Business Settings (single canonical record)
  await db.prepare(
    `INSERT OR IGNORE INTO business_settings (
      id, trading_name, legal_entity, phone_display, phone_e164,
      address_display, address_verified, hours_display, timezone,
      monitored_inbox, recruiting_contact, privacy_contact,
      roc_numbers, roc_verification_notes, insurance_statement,
      service_area_cities_json, updated_at, updated_by
    ) VALUES (1, ?, ?, ?, ?, ?, 0, ?, 'America/Phoenix', ?, ?, ?, ?, ?, ?, ?, ?, 'seed')`
  ).run(
    'Service Maintenance',
    'Promptitude Inc.',
    '(480) 423-9196',
    '+14804239196',
    '2105 S Hardy Dr., Suite 17, Tempe, AZ (Confirm full ZIP & walk-in status prior to launch)',
    'Monday – Friday, 7:00 AM – 5:00 PM (America/Phoenix)',
    'service@smiaz.com',
    'careers@smiaz.com',
    'privacy@smiaz.com',
    'ROC 334827, ROC 328349, ROC 328350',
    'Verify legal entity linkage, active status, classifications, and official AZ ROC URLs before launch.',
    'Insurance documentation available on request (General Liability, Umbrella, Auto, Workers Compensation)',
    JSON.stringify(['Phoenix', 'Tempe', 'Scottsdale', 'Mesa', 'Chandler', 'Gilbert', 'Glendale', 'Peoria', 'Goodyear']),
    now
  );

  // 2. Staff Users (7 RBAC roles)
  const devPassHash = hashPassword('SM-Staff-2026!');
  for (const u of DEMO_USERS) {
    await db.prepare(
      `INSERT OR IGNORE INTO users (user_id, email, full_name, password_hash, role, extra_roles_json, totp_secret, mfa_enabled, active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, '[]', ?, 1, 1, ?, ?)`
    ).run(u.user_id, u.email, u.full_name, devPassHash, u.role, u.totp_secret, now, now);
  }

  // 3. Pages & initial approved/draft revisions
  for (const p of SEED_PAGES) {
    await db.prepare(
      `INSERT OR IGNORE INTO pages (
        page_id, slug, template, title, service_family, owner_name,
        editorial_state, activation_state, is_conditional, indexable,
        current_revision, published_revision, review_date, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`
    ).run(
      p.page_id,
      p.slug,
      p.template,
      p.title,
      p.service_family,
      p.owner_name,
      p.editorial_state,
      p.activation_state,
      p.is_conditional,
      p.indexable,
      p.activation_state === 'Live' ? 1 : null,
      now.slice(0, 10),
      now
    );

    await db.prepare(
      `INSERT OR IGNORE INTO page_revisions (
        revision_id, page_id, revision_number, title, meta_title, meta_description,
        hero_headline, hero_summary, cta_label, cta_route, body_html,
        scopes_json, faqs_json, claim_status, author_id, approver_id, editorial_state, created_at
      ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'usr-editor-01', ?, ?, ?)`
    ).run(
      `rev-${p.page_id}-1`,
      p.page_id,
      p.title,
      p.meta_title,
      p.meta_description,
      p.hero_headline,
      p.hero_summary,
      p.cta_label,
      p.cta_route,
      p.body_html,
      JSON.stringify(p.scopes || []),
      JSON.stringify(p.faqs || []),
      p.editorial_state === 'Approved' ? 'approved for publication' : 'proposed wording',
      p.editorial_state === 'Approved' ? 'usr-publisher-01' : null,
      p.editorial_state,
      now
    );
  }

  // 4. Claims & evidence inventory
  for (const c of SEED_CLAIMS) {
    await db.prepare(
      `INSERT OR IGNORE INTO testimonials_claims (
        claim_id, claim_type, title, exact_text, attribution, evidence_source,
        owner_name, status, allowed_placements_json, review_date, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(c.claim_id, c.claim_type, c.title, c.exact_text, c.attribution, c.evidence_source, c.owner_name, c.status, c.allowed_placements_json, now.slice(0, 10), now);
  }

  // 5. Legacy Redirects
  for (const r of SEED_REDIRECTS) {
    await db.prepare(
      `INSERT OR IGNORE INTO redirects (redirect_id, old_path, destination_path, status_code, reason, author_name, active, created_at, updated_at)
       VALUES (?, ?, ?, 301, ?, 'System Migration Seed', 1, ?, ?)`
    ).run(generateUuid(), r.old_path, r.destination_path, r.reason, now, now);
  }

  // 6. Editorial Articles (all Draft/Unpublished at launch until reviewed/approved)
  for (const a of SEED_ARTICLES) {
    await db.prepare(
      `INSERT OR IGNORE INTO articles (
        article_id, slug, title, buyer_target, related_service, summary, body_html,
        sources_note, author_name, editorial_state, activation_state, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(a.article_id, a.slug, a.title, a.buyer_target, a.related_service, a.summary, a.body_html, a.sources_note, a.author_name, a.editorial_state, a.activation_state, now);
  }

  // 7. Clearly marked PRIVATE STAGING TEST records (NOT published publicly, preserving truthful empty states!)
  await db.prepare(
    `INSERT OR IGNORE INTO jobs (
      requisition_id, opening_cycle_id, slug, title, role_family, employment_type,
      work_area, schedule_text, travel_requirements, responsibilities_html, qualifications_html,
      pay_info, benefits_info, status, form_revision, require_city_zip, resume_policy,
      questions_json, hiring_owner_id, backup_owner_id, assigned_reviewers_json, is_private_test, updated_at
    ) VALUES (
      'REQ-TEST-2026-001', 'CYCLE-TEST-01', 'private-test-day-porter-tempe',
      '[PRIVATE STAGING TEST] Commercial Day Porter — East Valley',
      'Day Porter', 'Full-time', 'Tempe / Mesa / Chandler Commercial Centers',
      'Monday – Friday, 6:30 AM – 3:00 PM (America/Phoenix)',
      'Valid driver license and reliable transportation between assigned sites.',
      '<p>Private staging test vacancy for staff acceptance training. Do not publish as an active opening without owner-approved pay and role approval.</p>',
      '<p>Previous commercial property upkeep or porter experience preferred; training provided.</p>',
      'Pending Hiring Owner approval (not for public display)', 'Pending owner confirmation',
      'Draft', 1, 1, 'optional',
      ?, 'usr-hiring-owner-01', 'usr-hiring-owner-01', ?, 1, ?
    )`
  ).run(
    JSON.stringify([
      { id: 'az_dl', label: 'Do you hold a valid driver license for travel between assigned properties?', type: 'select', options: ['Yes', 'No'], required: true },
      { id: 'shift_ok', label: 'Are you available for morning shifts starting at 6:30 AM?', type: 'select', options: ['Yes', 'No'], required: true },
    ]),
    JSON.stringify(['usr-hiring-reviewer-01']),
    now
  );

  await db.prepare(
    `INSERT OR IGNORE INTO projects (
      project_id, slug, title, is_private_test, naming_decision, client_name_internal,
      property_type, city_region, completion_date, completion_documented, client_permission_verified,
      challenge, agreed_scope, delivery_role, self_performed_notes, coordinated_notes,
      operating_constraints, completed_work, verified_result, related_services_json,
      editorial_state, activation_state, owner_id, updated_at
    ) VALUES (
      'proj-private-test-01', 'private-test-warehouse-scrim',
      '[PRIVATE STAGING TEST] Industrial Bay Scrim & Concrete Spall Repair',
      1, 'anonymized', 'Internal Training Record Only',
      'Industrial / Warehouse', 'Tempe / Greater Phoenix', '2026-10-15', 0, 0,
      'Private training draft demonstrating project narrative fields and before/after pairing readiness.',
      'Replace damaged roof-deck scrim section and patch dock apron concrete spall.',
      'In-house maintenance technicians with rented scissor lift.',
      'Surface prep, scrim replacement, concrete repair.',
      'Lift rental arranged for off-shift bay window.',
      'Active forklift aisle barricaded during morning maintenance window.',
      'Draft staging record — awaiting genuine completion evidence and photo upload before any publication.',
      'Private test record only; not published.',
      '["warehouse-repairs","commercial-maintenance"]',
      'Draft', 'Unpublished', 'usr-contributor-01', ?
    )`
  ).run(now);

  // 8. Draft Seasonal Campaign template (not Live at launch)
  const startNextWeek = new Date(Date.now() + 7 * 86_400_000).toISOString();
  const endNextMonth = new Date(Date.now() + 37 * 86_400_000).toISOString();
  await db.prepare(
    `INSERT OR IGNORE INTO campaigns (
      campaign_id, slug, internal_title, service_family, owner_name,
      placement_slot, target_service_slugs_json, heading, summary,
      cta_label, cta_destination, priority, start_at, end_at, is_evergreen,
      editorial_state, activation_state, landing_page_enabled, landing_page_noindex,
      landing_expiry_policy, content_revision, updated_at
    ) VALUES (
      'camp-pre-summer-draft', 'pre-summer-upkeep',
      '[DRAFT TEMPLATE] Pre-Summer Exterior & Drainage Upkeep',
      'exterior-site-maintenance', 'Marcus Chen',
      'homepage_feature', '["/services/exterior-site-maintenance/","/services/recurring-property-care/"]',
      'Pre-summer roof debris, drainage, and exterior walkthroughs',
      'Schedule an exterior property check for scuppers, downspouts, walkways, and sun-exposed finishes ahead of peak Valley heat.',
      'Request a property assessment', '/request-proposal/?service=exterior-site-maintenance',
      10, ?, ?, 0,
      'Draft', 'Unpublished', 1, 1, 'ended_notice', 1, ?
    )`
  ).run(startNextWeek, endNextMonth, now);

  return { ok: true };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const db = await getDb();
  await seedDatabase(db);
  console.log('Seed completed successfully:', db.dialect === 'postgres' ? `Neon Postgres (${ENV.NEON_BRANCH || 'default'})` : ENV.DB_PATH);
  await db.close();
}
