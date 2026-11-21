import { auditEmailDnsSecurity } from '../threatRules.ts';
import { resolveDnsRecord, type ScanModulePlugin } from './types.ts';

export const dnsModule: ScanModulePlugin = {
  id: 'dns',
  label: 'DNS, SPF, DMARC & CAA',
  isActive: false,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    const [aRecs, aaaaRecs, mxRecs, nsRecs, txtRecs, dmarcRecs, caaRecs] =
      await Promise.all([
        resolveDnsRecord(ctx.host, 'A'),
        resolveDnsRecord(ctx.host, 'AAAA'),
        resolveDnsRecord(ctx.host, 'MX'),
        resolveDnsRecord(ctx.host, 'NS'),
        resolveDnsRecord(ctx.host, 'TXT'),
        resolveDnsRecord(`_dmarc.${ctx.host}`, 'TXT'),
        resolveDnsRecord(ctx.host, 'CAA'),
      ]);

    const emailSec = auditEmailDnsSecurity(txtRecs, dmarcRecs);
    ctx.dns = {
      a: aRecs,
      aaaa: aaaaRecs,
      mx: mxRecs,
      ns: nsRecs,
      txt: txtRecs,
      caa: caaRecs,
      spfRecord: emailSec.spfRecord,
      dmarcRecord: emailSec.dmarcRecord,
      emailSecurityStatus: emailSec.emailSecurityStatus,
    };
  },
};
