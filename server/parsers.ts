import { XMLParser } from 'fast-xml-parser';
import type {
  Citation,
  NewsItem,
  ResearchPaper,
  WorldBankMetric,
} from '../src/types/intelligence.ts';

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  trimValues: true,
});

export function stripHtml(input: string | undefined | null): string {
  if (!input) return '';
  return String(input)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(?:[^>"']|"[^"]*"|'[^']*')*>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#039;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, '');
  } catch {
    return 'source';
  }
}

export interface GroundingChunkLike {
  web?: {
    uri?: string;
    title?: string;
  };
}

export function extractGroundingCitations(
  chunks: GroundingChunkLike[] | undefined | null,
): Citation[] {
  if (!Array.isArray(chunks)) return [];
  const seen = new Set<string>();
  const citations: Citation[] = [];

  for (const chunk of chunks) {
    const uri = chunk?.web?.uri?.trim();
    if (!uri || !/^https?:\/\//i.test(uri)) continue;
    if (seen.has(uri)) continue;
    seen.add(uri);
    const domain = extractDomain(uri);
    const title = (chunk?.web?.title ?? '').trim() || domain;
    citations.push({ title, url: uri, domain });
  }
  return citations;
}

export function extractJsonFromText<T>(rawText: string, fallback: T): T {
  if (!rawText || typeof rawText !== 'string') return fallback;
  const trimmed = rawText.trim();

  // Try direct parse first
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    // Continue to fence / substring extraction
  }

  // Try markdown ```json ... ``` or ``` ... ``` block
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch?.[1]) {
    try {
      return JSON.parse(fenceMatch[1].trim()) as T;
    } catch {
      // Continue
    }
  }

  // Try finding outermost JSON object or array
  const firstBrace = trimmed.indexOf('{');
  const firstBracket = trimmed.indexOf('[');
  let start = -1;
  let end = -1;

  if (firstBrace !== -1 && (firstBracket === -1 || firstBrace < firstBracket)) {
    start = firstBrace;
    end = trimmed.lastIndexOf('}');
  } else if (firstBracket !== -1) {
    start = firstBracket;
    end = trimmed.lastIndexOf(']');
  }

  if (start !== -1 && end > start) {
    const candidate = trimmed.slice(start, end + 1);
    try {
      return JSON.parse(candidate) as T;
    } catch {
      return fallback;
    }
  }

  return fallback;
}

function asArray<T>(val: T | T[] | undefined | null): T[] {
  if (val == null) return [];
  return Array.isArray(val) ? val : [val];
}

function inferArxivCategory(categories: string[]): ResearchPaper['category'] {
  const joined = categories.join(' ').toLowerCase();
  if (joined.includes('econ') || joined.includes('q-fin')) return 'Economics';
  if (joined.includes('q-bio')) return 'Biomedical';
  if (
    joined.includes('cs.ai') ||
    joined.includes('cs.cl') ||
    joined.includes('cs.lg') ||
    joined.includes('cs.cv') ||
    joined.includes('cs.')
  ) {
    return 'AI & Tech';
  }
  return 'Physics & Science';
}

export function parseArxivAtom(xml: string): ResearchPaper[] {
  if (!xml || typeof xml !== 'string') return [];
  const parsed = xmlParser.parse(xml) as {
    feed?: {
      entry?: unknown;
    };
  };
  const entries = asArray(parsed?.feed?.entry) as Array<Record<string, unknown>>;

  return entries
    .map((entry, idx) => {
      const rawId = typeof entry.id === 'string' ? entry.id.trim() : `arxiv-${idx}`;
      const title = stripHtml(typeof entry.title === 'string' ? entry.title : '');
      const abstract = stripHtml(
        typeof entry.summary === 'string' ? entry.summary : '',
      );
      const publishedAt =
        typeof entry.published === 'string'
          ? entry.published
          : typeof entry.updated === 'string'
            ? entry.updated
            : '';

      const rawAuthors = asArray(
        entry.author as Record<string, unknown> | Array<Record<string, unknown>>,
      );
      const authors = rawAuthors
        .map((a) => (typeof a?.name === 'string' ? a.name.trim() : ''))
        .filter(Boolean)
        .slice(0, 4);

      const rawCats = asArray(
        entry.category as Record<string, unknown> | Array<Record<string, unknown>>,
      );
      const catTerms = rawCats
        .map((c) => (typeof c?.['@_term'] === 'string' ? c['@_term'] : ''))
        .filter(Boolean);

      const links = asArray(
        entry.link as Record<string, unknown> | Array<Record<string, unknown>>,
      );
      const htmlLink = links.find(
        (l) => typeof l?.['@_href'] === 'string' && l?.['@_rel'] === 'alternate',
      )?.['@_href'] as string | undefined;
      const url = htmlLink || rawId;

      return {
        id: `arxiv-${rawId.split('/').pop() ?? idx}`,
        title,
        authors,
        abstract,
        publishedAt,
        source: 'arXiv' as const,
        category: inferArxivCategory(catTerms),
        url,
      };
    })
    .filter((p) => p.title.length > 0);
}

export function parseRssFeed(
  xml: string,
  sourceName: string,
  sourceKey: NewsItem['sourceKey'],
): NewsItem[] {
  if (!xml || typeof xml !== 'string') return [];
  const parsed = xmlParser.parse(xml) as {
    rss?: { channel?: { item?: unknown } };
    feed?: { entry?: unknown };
  };

  // Standard RSS 2.0
  const rssItems = asArray(parsed?.rss?.channel?.item) as Array<
    Record<string, unknown>
  >;
  if (rssItems.length > 0) {
    return rssItems
      .map((item, idx) => {
        const title = stripHtml(
          typeof item.title === 'string'
            ? item.title
            : typeof (item.title as Record<string, unknown>)?.['#text'] === 'string'
              ? ((item.title as Record<string, unknown>)['#text'] as string)
              : '',
        );
        const rawSummary =
          typeof item.description === 'string'
            ? item.description
            : typeof item['content:encoded'] === 'string'
              ? item['content:encoded']
              : '';
        const summary = stripHtml(rawSummary).slice(0, 320);
        const url =
          typeof item.link === 'string'
            ? item.link.trim()
            : typeof (item.guid as Record<string, unknown>)?.['#text'] === 'string'
              ? ((item.guid as Record<string, unknown>)['#text'] as string)
              : '';
        const publishedAt =
          typeof item.pubDate === 'string'
            ? item.pubDate
            : typeof item['dc:date'] === 'string'
              ? item['dc:date']
              : '';
        return {
          id: `${sourceKey}-${idx}-${url.slice(-16)}`,
          title,
          summary,
          source: sourceName,
          sourceKey,
          publishedAt,
          url,
        };
      })
      .filter((item) => item.title.length > 0 && item.url.startsWith('http'));
  }

  // Atom fallback
  const atomEntries = asArray(parsed?.feed?.entry) as Array<
    Record<string, unknown>
  >;
  return atomEntries
    .map((entry, idx) => {
      const title = stripHtml(typeof entry.title === 'string' ? entry.title : '');
      const summary = stripHtml(
        typeof entry.summary === 'string'
          ? entry.summary
          : typeof entry.content === 'string'
            ? entry.content
            : '',
      ).slice(0, 320);
      const links = asArray(
        entry.link as Record<string, unknown> | Array<Record<string, unknown>>,
      );
      const url =
        (links.find((l) => typeof l?.['@_href'] === 'string')?.['@_href'] as
          | string
          | undefined) ?? '';
      const publishedAt =
        typeof entry.published === 'string'
          ? entry.published
          : typeof entry.updated === 'string'
            ? entry.updated
            : '';
      return {
        id: `${sourceKey}-${idx}-${url.slice(-16)}`,
        title,
        summary,
        source: sourceName,
        sourceKey,
        publishedAt,
        url,
      };
    })
    .filter((item) => item.title.length > 0 && item.url.startsWith('http'));
}

export function formatCompactNumber(num: number, prefix = '', suffix = ''): string {
  if (!Number.isFinite(num)) return 'Unavailable';
  const abs = Math.abs(num);
  if (abs >= 1e12) return `${prefix}${(num / 1e12).toFixed(2)}T${suffix}`;
  if (abs >= 1e9) return `${prefix}${(num / 1e9).toFixed(2)}B${suffix}`;
  if (abs >= 1e6) return `${prefix}${(num / 1e6).toFixed(2)}M${suffix}`;
  if (abs >= 1e3) return `${prefix}${(num / 1e3).toFixed(1)}K${suffix}`;
  return `${prefix}${num.toFixed(2)}${suffix}`;
}

export interface WorldBankIndicatorSpec {
  id: string;
  label: string;
  unit: string;
  format: 'currency_compact' | 'currency' | 'percent' | 'count_compact';
}

export function normalizeWorldBankSeries(
  spec: WorldBankIndicatorSpec,
  payload: unknown,
): WorldBankMetric | null {
  if (!Array.isArray(payload) || payload.length < 2 || !Array.isArray(payload[1])) {
    return null;
  }
  const rows = payload[1] as Array<{ value?: number | null; date?: string }>;
  const latestValid = rows.find(
    (r) => typeof r?.value === 'number' && Number.isFinite(r.value),
  );
  if (!latestValid || typeof latestValid.value !== 'number') return null;

  let formatted = '';
  switch (spec.format) {
    case 'currency_compact':
      formatted = formatCompactNumber(latestValid.value, '$');
      break;
    case 'currency':
      formatted = `$${latestValid.value.toLocaleString('en-US', {
        maximumFractionDigits: 0,
      })}`;
      break;
    case 'percent':
      formatted = `${latestValid.value.toFixed(2)}%`;
      break;
    case 'count_compact':
      formatted = formatCompactNumber(latestValid.value);
      break;
  }

  return {
    indicatorId: spec.id,
    label: spec.label,
    value: formatted,
    year: String(latestValid.date ?? ''),
    unit: spec.unit,
  };
}
