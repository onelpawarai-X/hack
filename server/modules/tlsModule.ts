import tls from 'node:tls';
import type { TargetScanResult } from '../../src/types/cyber.ts';
import type { ScanModulePlugin } from './types.ts';

export async function inspectTlsCertificate(
  host: string,
): Promise<TargetScanResult['tls']> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (res: TargetScanResult['tls']) => {
      if (!settled) {
        settled = true;
        resolve(res);
      }
    };

    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || undefined;
          const cipherInfo = socket.getCipher();
          const authorized = socket.authorized;
          socket.end();

          if (!cert || !cert.subject) {
            return finish({ valid: false, error: 'No peer certificate presented' });
          }
          const validToDate = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining = validToDate
            ? Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : undefined;
          const issuerParts = [cert.issuer?.O, cert.issuer?.CN].filter(Boolean);
          const subjectParts = [cert.subject?.CN, cert.subject?.O].filter(Boolean);
          const sanCount = cert.subjectaltname
            ? cert.subjectaltname.split(',').length
            : undefined;

          finish({
            valid: authorized && (daysRemaining === undefined || daysRemaining >= 0),
            issuer: issuerParts.join(' · ') || 'Unknown Issuer',
            subject: subjectParts.join(' · ') || host,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            protocol,
            cipher: cipherInfo?.name || undefined,
            sanCount,
          });
        } catch (err) {
          socket.destroy();
          finish({
            valid: false,
            error: err instanceof Error ? err.message : 'TLS inspection failed',
          });
        }
      },
    );

    socket.setTimeout(5000, () => {
      socket.destroy();
      finish({ valid: false, error: 'TLS handshake timed out on port 443' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      finish({ valid: false, error: err.message });
    });
  });
}

export const tlsModule: ScanModulePlugin = {
  id: 'tls',
  label: 'TLS / SSL Certificate & Cipher',
  isActive: false,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    ctx.log(`Starting TLS handshake with ${ctx.host}:443`, 'info', 'tls');
    const certificate = await inspectTlsCertificate(ctx.host);
    ctx.tls = certificate;
    if (certificate?.valid) {
      ctx.log(
        `TLS handshake OK · ${certificate.protocol ?? 'TLS'} · ${certificate.issuer ?? 'trusted CA'} · ${certificate.daysRemaining ?? '?'} day(s) remaining`,
        'success',
        'tls',
      );
    } else {
      ctx.log(`TLS handshake failed · ${certificate?.error ?? 'invalid certificate'}`, 'error', 'tls');
    }
  },
};
