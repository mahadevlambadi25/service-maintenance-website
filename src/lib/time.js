import { BUSINESS_TZ } from '../config.js';

/**
 * Formats an ISO UTC timestamp or Date into explicit America/Phoenix local representation.
 * Arizona does not observe DST, remaining UTC-07:00 year-round.
 */
export function formatPhoenixDateTime(isoOrDate, includeTz = true) {
  if (!isoOrDate) return '—';
  const d = isoOrDate instanceof Date ? isoOrDate : new Date(isoOrDate);
  if (Number.isNaN(d.getTime())) return '—';
  const formatted = new Intl.DateTimeFormat('en-US', {
    timeZone: BUSINESS_TZ,
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  }).format(d);
  return includeTz ? `${formatted} (America/Phoenix)` : formatted;
}

export function formatPhoenixDate(isoOrDate) {
  if (!isoOrDate) return '—';
  const d = isoOrDate instanceof Date ? isoOrDate : new Date(isoOrDate);
  if (Number.isNaN(d.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', {
    timeZone: BUSINESS_TZ,
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(d);
}

/**
 * Converts a Phoenix wall-clock datetime-local string ("YYYY-MM-DDTHH:MM" or "YYYY-MM-DDTHH:MM:SS")
 * explicitly to a UTC ISO string. Rejects invalid formats.
 */
export function phoenixLocalToUtcIso(localStr) {
  if (!localStr) return null;
  const trimmed = String(localStr).trim();
  // If already ISO with Z or offset, normalize directly
  if (/(Z|[+-]\d{2}:\d{2})$/.test(trimmed)) {
    const d = new Date(trimmed);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  const m = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  const [, y, mo, da, h, mi, s = '00'] = m;
  // America/Phoenix is strictly UTC-07:00 without DST
  const isoWithOffset = `${y}-${mo}-${da}T${h}:${mi}:${s}-07:00`;
  const d = new Date(isoWithOffset);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Converts a UTC ISO string to "YYYY-MM-DDTHH:MM" in America/Phoenix for HTML datetime-local inputs.
 */
export function utcIsoToPhoenixInput(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return '';
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: BUSINESS_TZ,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(d);
  const map = Object.fromEntries(parts.map((p) => [p.type, p.value]));
  const hour = map.hour === '24' ? '00' : map.hour;
  return `${map.year}-${map.month}-${map.day}T${hour}:${map.minute}`;
}

export function addBusinessDaysPhoenix(startDate, businessDays = 1, holidays = []) {
  const holidaySet = new Set(holidays);
  let cur = new Date(startDate);
  let added = 0;
  while (added < businessDays) {
    cur = new Date(cur.getTime() + 86_400_000);
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: BUSINESS_TZ,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      weekday: 'short',
    }).formatToParts(cur);
    const map = Object.fromEntries(parts.map((p) => [p.type, p.value]));
    const ymd = `${map.year}-${map.month}-${map.day}`;
    if (map.weekday !== 'Sat' && map.weekday !== 'Sun' && !holidaySet.has(ymd)) {
      added++;
    }
  }
  return cur.toISOString();
}
