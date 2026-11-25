import { SERVICE_FAMILIES } from '../config.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// Permits international E.164 or standard formatted phone numbers (7 to 20 digits)
const PHONE_RE = /^\+?[\d\s().-]{7,25}$/;

export function cleanText(val, maxLen = 500) {
  if (val === null || val === undefined) return '';
  return String(val).trim().slice(0, maxLen);
}

export function countDigits(str) {
  return (String(str || '').match(/\d/g) || []).length;
}

export function isValidEmail(val) {
  const v = cleanText(val, 254);
  return EMAIL_RE.test(v);
}

export function isValidPhone(val) {
  const v = cleanText(val, 40);
  if (!PHONE_RE.test(v)) return false;
  const digits = countDigits(v);
  return digits >= 7 && digits <= 15;
}

export function normalizePhone(val) {
  const v = cleanText(val, 40);
  if (!v) return '';
  const hasPlus = v.startsWith('+');
  const digits = v.replace(/\D/g, '');
  return hasPlus ? `+${digits}` : digits;
}

const VALID_SERVICES = new Set(SERVICE_FAMILIES.map((s) => s.id));
const VALID_PROPERTY_TYPES = new Set(['warehouse-industrial', 'retail', 'office', 'other-commercial', 'not-sure', '']);
const VALID_TIMING = new Set(['planning', 'upcoming', 'time-sensitive', 'flexible', 'date-range', '']);
const VALID_URGENCY = new Set(['routine', 'priority', 'time-sensitive']);

export function validateInquiryPayload(body) {
  const errors = {};
  const name = cleanText(body.name, 100);
  const company = cleanText(body.company, 150);
  const email = cleanText(body.email, 254);
  const telephone = cleanText(body.telephone, 40);
  const preferredMethod = cleanText(body.preferred_contact_method, 20);
  const serviceNeeded = cleanText(body.service_needed, 60);
  const propertyCityOrZip = cleanText(body.property_city_or_zip, 120);
  const description = cleanText(body.description, 3000);
  const propertyType = cleanText(body.property_type, 40);
  const desiredTiming = cleanText(body.desired_timing, 40);

  if (!name) errors.name = 'Enter your name (up to 100 characters).';
  if (!company) errors.company = 'Enter your company or organization name.';

  if (preferredMethod !== 'email' && preferredMethod !== 'telephone') {
    errors.preferred_contact_method = 'Select email or telephone as your preferred contact method.';
  } else if (preferredMethod === 'email') {
    if (!email || !isValidEmail(email)) {
      errors.email = 'Enter a valid email address (for example, name@company.com).';
    }
    if (telephone && !isValidPhone(telephone)) {
      errors.telephone = 'Enter a valid telephone number or leave it blank.';
    }
  } else if (preferredMethod === 'telephone') {
    if (!telephone || !isValidPhone(telephone)) {
      errors.telephone = 'Enter a valid telephone number (international numbers supported).';
    }
    if (email && !isValidEmail(email)) {
      errors.email = 'Enter a valid email address or leave it blank.';
    }
  }

  if (!serviceNeeded || !VALID_SERVICES.has(serviceNeeded)) {
    errors.service_needed = 'Select the service needed.';
  }
  if (!propertyCityOrZip) {
    errors.property_city_or_zip = 'Enter the property city or ZIP where the work is located.';
  }
  if (!description) {
    errors.description = 'Provide a brief description of what needs attention.';
  }
  if (!VALID_PROPERTY_TYPES.has(propertyType)) {
    errors.property_type = 'Select a valid property type.';
  }
  if (!VALID_TIMING.has(desiredTiming)) {
    errors.desired_timing = 'Select a valid timing option.';
  }

  return {
    valid: Object.keys(errors).length === 0,
    errors,
    data: {
      name,
      company,
      email: email.toLowerCase(),
      telephone,
      preferred_contact_method: preferredMethod,
      service_needed: serviceNeeded,
      property_city_or_zip: propertyCityOrZip,
      description,
      property_type: propertyType || 'not-sure',
      desired_timing: desiredTiming || 'flexible',
      multiple_properties: body.multiple_properties === true || body.multiple_properties === 'true' || body.multiple_properties === 'on',
      site_count: cleanText(body.site_count, 40),
      coverage_detail: cleanText(body.coverage_detail, 300),
      project_budget: cleanText(body.project_budget, 60),
      ti_property_address: cleanText(body.ti_property_address, 200),
      ti_occupancy: cleanText(body.ti_occupancy, 40),
      ti_plans_available: cleanText(body.ti_plans_available, 40),
      ti_bid_due_date: cleanText(body.ti_bid_due_date, 40),
      ti_completion_window: cleanText(body.ti_completion_window, 80),
      ti_landlord_involvement: cleanText(body.ti_landlord_involvement, 120),
      rc_frequency: cleanText(body.rc_frequency, 60),
      rc_site_size: cleanText(body.rc_site_size, 80),
      rc_current_arrangement: cleanText(body.rc_current_arrangement, 200),
      marketing_opt_in: body.marketing_opt_in === true || body.marketing_opt_in === 'true' || body.marketing_opt_in === 'on',
    },
  };
}

export function validateServiceRequestPayload(body) {
  const errors = {};
  const name = cleanText(body.name, 100);
  const company = cleanText(body.company, 150);
  const email = cleanText(body.email, 254);
  const telephone = cleanText(body.telephone, 40);
  const preferredMethod = cleanText(body.preferred_contact_method, 20);
  const property = cleanText(body.property, 200);
  const description = cleanText(body.description, 3000);
  const urgency = cleanText(body.urgency, 30) || 'routine';
  const referenceNumber = cleanText(body.reference_number, 80);

  if (!name) errors.name = 'Enter your name.';
  if (!company) errors.company = 'Enter your company or property management organization.';
  if (preferredMethod !== 'email' && preferredMethod !== 'telephone') {
    errors.preferred_contact_method = 'Choose email or telephone.';
  } else if (preferredMethod === 'email') {
    if (!email || !isValidEmail(email)) errors.email = 'Enter a valid email address.';
    if (telephone && !isValidPhone(telephone)) errors.telephone = 'Enter a valid telephone number.';
  } else {
    if (!telephone || !isValidPhone(telephone)) errors.telephone = 'Enter a valid telephone number.';
    if (email && !isValidEmail(email)) errors.email = 'Enter a valid email address.';
  }
  if (!property) errors.property = 'Identify the property name or location.';
  if (!description) errors.description = 'Describe the service request.';
  if (!VALID_URGENCY.has(urgency)) errors.urgency = 'Select a valid urgency level.';

  return {
    valid: Object.keys(errors).length === 0,
    errors,
    data: {
      name,
      company,
      email: email.toLowerCase(),
      telephone,
      preferred_contact_method: preferredMethod,
      property,
      description,
      urgency,
      reference_number: referenceNumber,
    },
  };
}

export function validateApplicationPayload(body, job) {
  const errors = {};
  const name = cleanText(body.name, 100);
  const preferredMethod = cleanText(body.preferred_contact_method, 20);
  const email = cleanText(body.email, 254);
  const telephone = cleanText(body.telephone, 40);
  const cityOrZip = cleanText(body.city_or_zip, 80);
  const relevantExperience = cleanText(body.relevant_experience, 5000);
  const availability = cleanText(body.availability, 300);
  const privacyAck = body.privacy_ack === true || body.privacy_ack === 'true' || body.privacy_ack === 'on';
  const hasResume = Boolean(body.has_resume);

  if (!name) errors.name = 'Enter your full name (up to 100 characters).';
  if (preferredMethod !== 'email' && preferredMethod !== 'telephone') {
    errors.preferred_contact_method = 'Select email or telephone as your preferred contact method.';
  } else if (preferredMethod === 'email') {
    if (!email || !isValidEmail(email)) errors.email = 'Enter a valid email address.';
    if (telephone && !isValidPhone(telephone)) errors.telephone = 'Enter a valid telephone number.';
  } else {
    if (!telephone || !isValidPhone(telephone)) errors.telephone = 'Enter a valid telephone number.';
    if (email && !isValidEmail(email)) errors.email = 'Enter a valid email address.';
  }

  if (job.require_city_zip && !cityOrZip) {
    errors.city_or_zip = 'Enter your city or ZIP for work-area review.';
  }

  // Experience text OR resume required depending on job policy
  if (job.resume_policy === 'required' && !hasResume && !relevantExperience) {
    errors.resume = 'Attach a PDF or DOCX resume, or use the alternative work-history field.';
  } else if (!hasResume && !relevantExperience) {
    errors.relevant_experience = 'Describe your relevant experience (or select No prior experience / attach a resume).';
  }

  // Validate role-specific questions
  let parsedQuestions = [];
  try {
    parsedQuestions = JSON.parse(job.questions_json || '[]');
  } catch {
    parsedQuestions = [];
  }
  const answers = {};
  for (const q of parsedQuestions) {
    const val = cleanText(body[`q_${q.id}`], 1000);
    if (q.required && !val) {
      errors[`q_${q.id}`] = `Please answer: ${q.label}`;
    }
    answers[q.id] = { label: q.label, answer: val };
  }

  if (!privacyAck) {
    errors.privacy_ack = 'Please acknowledge the applicant privacy notice before submitting.';
  }

  return {
    valid: Object.keys(errors).length === 0,
    errors,
    data: {
      name,
      preferred_contact_method: preferredMethod,
      email: email.toLowerCase(),
      telephone,
      city_or_zip: cityOrZip,
      relevant_experience: relevantExperience,
      availability,
      answers,
      privacy_ack: privacyAck,
    },
  };
}
