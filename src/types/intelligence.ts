export type Language = 'en' | 'bn';

export interface Citation {
  title: string;
  url: string;
  domain: string;
}

export interface BriefingSector {
  id: 'geopolitics' | 'economy' | 'ai_tech' | 'climate' | 'energy';
  title: string;
  headline: string;
  summary: string;
  impactLevel: 'High' | 'Elevated' | 'Moderate';
}

export interface WorldBriefingResponse {
  verifiedAt: string;
  cached: boolean;
  cacheExpiresAt: string;
  lang: Language;
  whatHappenedToday: string[];
  globalImpactAnalysis: string;
  sectors: BriefingSector[];
  citations: Citation[];
  searchQueries: string[];
  warning?: string;
}

export interface CryptoAsset {
  id: string;
  symbol: string;
  name: string;
  priceUsd: number;
  change24h: number | null;
}

export interface FxRate {
  pair: string;
  code: string;
  rate: number;
  source: string;
}

export interface GroundedMarketIndex {
  name: string;
  symbol: string;
  value: string;
  change: string;
  direction: 'up' | 'down' | 'flat' | 'unavailable';
  asOf: string;
}

export interface MarketsResponse {
  verifiedAt: string;
  cached: boolean;
  lang: Language;
  crypto: CryptoAsset[];
  fxRates: FxRate[];
  fxUpdatedAt: string | null;
  indicesAndCommodities: GroundedMarketIndex[];
  macroSentimentBrief: string;
  sentimentRegime: string;
  citations: Citation[];
  apiWarnings: string[];
}

export interface ResearchPaper {
  id: string;
  title: string;
  authors: string[];
  abstract: string;
  publishedAt: string;
  source: 'arXiv' | 'Crossref' | 'PubMed';
  category: 'AI & Tech' | 'Physics & Science' | 'Economics' | 'Biomedical';
  url: string;
  doi?: string;
}

export interface ResearchListResponse {
  verifiedAt: string;
  cached: boolean;
  papers: ResearchPaper[];
  apiWarnings: string[];
}

export interface PaperSummaryResponse {
  verifiedAt: string;
  lang: Language;
  plainSummary: string;
  keyTakeaways: string[];
  realWorldSignificance: string;
  citations: Citation[];
}

export interface NewsItem {
  id: string;
  title: string;
  summary: string;
  source: string;
  sourceKey: 'bbc' | 'aljazeera' | 'techcrunch' | 'un' | 'gdelt' | 'bing';
  publishedAt: string;
  url: string;
}

export interface NewsWireResponse {
  verifiedAt: string;
  cached: boolean;
  items: NewsItem[];
  apiWarnings: string[];
}

export interface NewsVerificationResponse {
  verifiedAt: string;
  lang: Language;
  verdict: 'Confirmed' | 'Developing' | 'Mixed Reports' | 'Unverified';
  confidenceNote: string;
  multiOutletAnalysis: string;
  verifiedFacts: string[];
  caveats: string;
  citations: Citation[];
}

export interface WorldBankMetric {
  indicatorId: string;
  label: string;
  value: string;
  year: string;
  unit: string;
}

export interface ExplorerDossierResponse {
  verifiedAt: string;
  cached: boolean;
  lang: Language;
  query: string;
  resolvedEntity: string;
  countryCode?: string;
  wikipediaSummary?: {
    title: string;
    description: string;
    extract: string;
    url: string;
  };
  wikidataEntity?: {
    id: string;
    label: string;
    description: string;
    url: string;
  };
  worldBankMetrics: WorldBankMetric[];
  aiBrief: string;
  keyFindings: string[];
  dataGaps: string;
  citations: Citation[];
  apiWarnings: string[];
}

export interface BrowseLink {
  label: string;
  url: string;
  domain: string;
  snippet?: string;
}

export interface BrowsePageResponse {
  mode: 'page' | 'search';
  url: string;
  title: string;
  domain: string;
  description: string;
  paragraphs: string[];
  links: BrowseLink[];
  fetchedAt: string;
  error?: string;
}
