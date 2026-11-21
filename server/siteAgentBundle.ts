import fs from 'node:fs';
import path from 'node:path';
import type { ZipEntry } from './zip.ts';

export interface SiteAgentBundleOptions {
  origin: string;
  version?: string;
}

export function buildSiteAgentBundle({ origin, version = '1.0.0' }: SiteAgentBundleOptions): ZipEntry[] {
  const agent = fs.readFileSync(path.resolve(process.cwd(), 'public', 'sentinel-agent.js'), 'utf8');
  let cleanOrigin = 'http://localhost';
  try {
    cleanOrigin = new URL(origin).origin;
  } catch {
    // Fall back to a safe placeholder instead of reflecting a malformed Host header.
  }
  const snippet = `<script src="${cleanOrigin}/sentinel-agent.js" data-mode="protect" defer></script>`;
  const readme = `# SentinelGlobe Site Agent

Version: ${version}
Control plane: ${cleanOrigin}

এই ফাইলটি আপনার ওয়েবসাইটে বসালে আপনার সাইটটি SentinelGlobe-এর সাথে যুক্ত হবে।
This package connects your website to the SentinelGlobe monitoring and defense network.

## কী কী দিচ্ছি / What is included

- \`sentinel-agent.js\` — browser-side agent that reports clickjacking, injected scripts and
  iframes, mixed content, form hijacking and CSP violations.
- Automatic site registration: the first beacon from your origin appears in the SentinelGlobe
  Website Network list. No manual account is needed.
- Domain ownership verification: a beacon from the matching origin is treated as proof, and
  DNS TXT, well-known HTTP file and HTML meta-tag verification are also available from the dashboard.
- Threat events per site: attack counts, last beacon, online/offline state and shield state.
- One-click protection: create a shield for your domain from the Website Network section.
- Downloadable firewall bundle for that shield: Nginx deny list, iptables script, Cloudflare
  WAF expression and DNS sinkhole hosts file.
- Client-side protection mode (\`data-mode="protect"\`) removes known-bad injected resources.

## কী দিচ্ছি না / What is not included

- 100% protection is not possible. This agent is one layer. Use HTTPS, a server-side WAF,
  patched software, strong authentication and backups as well.
- This agent does not replace a server-side WAF, a CDN or an operating-system firewall.
- It does not read private camera feeds, cookies, passwords or form values.
- It does not guarantee removal of a compromise that already exists on the server.

## ইনস্টল / Install

Add this line before \`</head>\` or before \`</body>\`:

\`\`\`html
${snippet}
\`\`\`

If you use a Content-Security-Policy, allow the control-plane origin in \`script-src\` and
\`connect-src\`.

## ডোমেইন মালিকানা যাচাই / Domain ownership verification

Choose any one method in the dashboard:

1. DNS TXT at \`_sentinelglobe-verify.<your-domain>\`
2. A file at \`https://<your-domain>/.well-known/sentinelglobe-verify.txt\`
3. A meta tag in your home page \`<head>\`:

\`\`\`html
<meta name="sentinelglobe-site-verification" content="sentinelglobe-verify=...">
\`\`\`

The dashboard shows the exact token for your domain.

## কী ডেটা যায় / Data sent

The agent sends only security telemetry to \`POST /api/agent/beacon\`:

- page URL and origin
- user agent
- detected issue type and a short description
- a random page-view id

It does not send cookies, passwords, form values, keystrokes or screenshots.

## যাচাই / Verify

1. Open your website in a browser.
2. Open the SentinelGlobe dashboard and find your domain under **Website network**.
3. The site should appear within 30 seconds. If it does not, check the browser console and
   your CSP rules.
4. Click **Protect** to create a shield. Download the firewall bundle and apply it on your
   web server or CDN.

## সমর্থন / Support

Control plane: ${cleanOrigin}
Health check: ${cleanOrigin}/api/health
Agent source: ${cleanOrigin}/sentinel-agent.js

## সীমাবদ্ধতা / Limitations

- Browser agents can be bypassed by a determined attacker.
- The agent only sees the page where it is loaded.
- Automatic removal is best-effort and depends on the browser and CSP.
- Firewall bundles must be reviewed and deployed by the site owner.
`;
  const install = `SentinelGlobe installation
==========================

1. Copy sentinel-agent.js to your website root, or use the hosted copy:

   ${cleanOrigin}/sentinel-agent.js

2. Add this tag to every page you want to monitor:

   ${snippet}

3. Open the page. The site appears in the SentinelGlobe Website Network list.

4. From the dashboard, verify ownership if needed and click Protect.

5. Download and apply the generated firewall bundle on your server or CDN.

Read README.md for the full list of capabilities and limitations.
`;
  return [
    { name: 'sentinel-agent.js', data: agent },
    { name: 'README.md', data: readme },
    { name: 'INSTALL.txt', data: install },
    { name: 'snippet.html', data: `${snippet}\n` },
    { name: 'VERSION.txt', data: `${version}\n` },
  ];
}
