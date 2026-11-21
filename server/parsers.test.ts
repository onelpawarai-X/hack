import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractGroundingCitations,
  extractJsonFromText,
  normalizeWorldBankSeries,
  parseArxivAtom,
  parseRssFeed,
} from './parsers.ts';

test('extractGroundingCitations deduplicates URLs and filters invalid links', () => {
  const citations = extractGroundingCitations([
    { web: { uri: 'https://www.reuters.com/world/story-1', title: 'Reuters Story' } },
    { web: { uri: 'https://www.reuters.com/world/story-1', title: 'Duplicate' } },
    { web: { uri: 'not-a-url', title: 'Broken' } },
    { web: { uri: 'https://apnews.com/article/2' } },
  ]);

  assert.equal(citations.length, 2);
  assert.equal(citations[0].domain, 'reuters.com');
  assert.equal(citations[0].title, 'Reuters Story');
  assert.equal(citations[1].domain, 'apnews.com');
  assert.equal(citations[1].title, 'apnews.com');
});

test('extractJsonFromText parses fenced JSON and raw objects safely', () => {
  const fenced = 'Here is the verified briefing:\n```json\n{"status":"ok","items":[1,2]}\n```';
  const parsed = extractJsonFromText(fenced, { status: 'fail', items: [] });
  assert.equal(parsed.status, 'ok');
  assert.deepEqual(parsed.items, [1, 2]);

  const broken = 'No JSON here at all';
  const fallback = extractJsonFromText(broken, { status: 'fallback' });
  assert.equal(fallback.status, 'fallback');
});

test('parseArxivAtom parses Atom entries with categories and authors', () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
  <feed xmlns="http://www.w3.org/2005/Atom">
    <entry>
      <id>http://arxiv.org/abs/2611.01234v1</id>
      <published>2026-11-19T18:00:00Z</published>
      <title>Scaling Verifiable Reasoning in Frontier Models</title>
      <summary>We investigate &lt;b&gt;verifiable&lt;/b&gt; multi-step reasoning.</summary>
      <author><name>A. Rahman</name></author>
      <author><name>M. Chen</name></author>
      <category term="cs.AI" />
      <link rel="alternate" href="https://arxiv.org/abs/2611.01234" />
    </entry>
  </feed>`;

  const papers = parseArxivAtom(xml);
  assert.equal(papers.length, 1);
  assert.equal(papers[0].source, 'arXiv');
  assert.equal(papers[0].category, 'AI & Tech');
  assert.deepEqual(papers[0].authors, ['A. Rahman', 'M. Chen']);
  assert.equal(papers[0].url, 'https://arxiv.org/abs/2611.01234');
  assert.equal(papers[0].abstract, 'We investigate verifiable multi-step reasoning.');
});

test('parseRssFeed parses RSS 2.0 items and strips HTML', () => {
  const rss = `<?xml version="1.0" encoding="UTF-8"?>
  <rss version="2.0">
    <channel>
      <title>BBC World</title>
      <item>
        <title><![CDATA[Global Climate Accord Reaches Milestone]]></title>
        <description><![CDATA[<p>Delegates agreed on new <b>grid</b> targets.</p>]]></description>
        <link>https://www.bbc.com/news/world-12345</link>
        <pubDate>Thu, 19 Nov 2026 14:30:00 GMT</pubDate>
      </item>
    </channel>
  </rss>`;

  const items = parseRssFeed(rss, 'BBC News', 'bbc');
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'Global Climate Accord Reaches Milestone');
  assert.equal(items[0].summary, 'Delegates agreed on new grid targets.');
  assert.equal(items[0].sourceKey, 'bbc');
});

test('normalizeWorldBankSeries picks latest non-null observation and formats compactly', () => {
  const payload = [
    { page: 1 },
    [
      { date: '2025', value: null },
      { date: '2024', value: 451234000000 },
    ],
  ];
  const metric = normalizeWorldBankSeries(
    { id: 'NY.GDP.MKTP.CD', label: 'GDP (Current US$)', unit: 'USD', format: 'currency_compact' },
    payload,
  );
  assert.ok(metric);
  assert.equal(metric.value, '$451.23B');
  assert.equal(metric.year, '2024');
});
