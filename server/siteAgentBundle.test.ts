import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildSiteAgentBundle } from './siteAgentBundle.ts';

test('site agent bundle contains the agent, install guide and honest limitations', () => {
  const files = buildSiteAgentBundle({ origin: 'https://sentinel.example.com/' });
  const names = files.map((file) => file.name);
  assert.deepEqual(names, ['sentinel-agent.js', 'README.md', 'INSTALL.txt', 'snippet.html', 'VERSION.txt']);
  const readme = String(files.find((file) => file.name === 'README.md')?.data);
  assert.match(readme, /https:\/\/sentinel\.example\.com\/sentinel-agent\.js/);
  assert.match(readme, /100% protection is not possible/i);
  assert.match(readme, /does not send cookies, passwords, form values/i);
  const snippet = String(files.find((file) => file.name === 'snippet.html')?.data);
  assert.equal(snippet.trim(), '<script src="https://sentinel.example.com/sentinel-agent.js" data-mode="protect" defer></script>');
});
