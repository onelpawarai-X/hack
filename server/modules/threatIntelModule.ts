import { threatMonitor } from '../threatMonitor.ts';
import { analyzeUrlTrapHeuristics, isValidIpv4 } from '../threatRules.ts';
import type { ScanModulePlugin } from './types.ts';

export const threatIntelModule: ScanModulePlugin = {
  id: 'threatIntel',
  label: 'Threat Intelligence Feed Matching',
  isActive: false,
  supportsTargetType: (t) => t === 'ip' || t === 'domain' || t === 'url',
  async run(ctx) {
    await threatMonitor.getSnapshot(false);

    if (ctx.targetType === 'ip') {
      ctx.feedMatches.push(...threatMonitor.lookupIpMatches(ctx.host));
      if (threatMonitor.isTorExitIp(ctx.host)) {
        ctx.feedMatches.push({
          feed: 'Tor Project Exit List',
          detail: 'IP operates as an active Tor Network Exit Node',
        });
      }
      return;
    }

    ctx.heuristicWarnings.push(
      ...analyzeUrlTrapHeuristics(ctx.probeUrl || ctx.normalizedTarget),
    );
    ctx.feedMatches.push(...threatMonitor.lookupUrlMatches(ctx.probeUrl, ctx.host));

    // Also cross-reference any resolved A-records against live threat feeds
    const resolvedIpv4s = ctx.dns.a.filter((r) => isValidIpv4(r)).slice(0, 3);
    for (const ip of resolvedIpv4s) {
      for (const m of threatMonitor.lookupIpMatches(ip)) {
        const detail = `Resolved host IP ${ip}: ${m.detail}`;
        if (!ctx.feedMatches.some((existing) => existing.detail === detail)) {
          ctx.feedMatches.push({ feed: m.feed, detail });
        }
      }
    }
  },
};
