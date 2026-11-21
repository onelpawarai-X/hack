import type { Language } from '../types/intelligence';

export function formatUtcTimestamp(iso: string | null | undefined, lang: Language = 'en'): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat(lang === 'bn' ? 'bn-BD' : 'en-GB', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
    hour12: false,
  }).format(date) + ' UTC';
}

export function formatCurrencyUsd(value: number): string {
  if (!Number.isFinite(value)) return '—';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: value < 10 ? 2 : 2,
    maximumFractionDigits: value < 10 ? 4 : 2,
  }).format(value);
}

export function formatSignedPercent(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return '—';
  const sign = value > 0 ? '+' : '';
  return `${sign}${value.toFixed(2)}%`;
}

export function formatShortDate(raw: string): string {
  if (!raw) return '';
  // Handle GDELT YYYYMMDDTHHMMSSZ format
  const gdeltMatch = raw.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})/);
  if (gdeltMatch) {
    return `${gdeltMatch[1]}-${gdeltMatch[2]}-${gdeltMatch[3]} ${gdeltMatch[4]}:${gdeltMatch[5]} UTC`;
  }
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw.slice(0, 16);
  return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}
