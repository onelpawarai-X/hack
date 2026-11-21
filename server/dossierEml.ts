import type { AttackerDossier } from './attackerDossier.ts';

export function buildDossierEml(dossier: AttackerDossier, from: string, to: string[]): string {
  const boundary = `sentinel-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  const jsonBase64 = Buffer.from(JSON.stringify(dossier, null, 2), 'utf8').toString('base64');
  const textBase64 = Buffer.from(dossier.reportText, 'utf8').toString('base64');
  return [
    `From: ${from}`,
    `To: ${to.join(', ')}`,
    `Subject: [SentinelGlobe] Forensic dossier — attacker ${dossier.ip} (${dossier.risk.severity})`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    textBase64,
    '',
    `--${boundary}`,
    'Content-Type: application/json; name="dossier.json"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="dossier.json"',
    '',
    jsonBase64,
    '',
    `--${boundary}--`,
    '',
  ].join('\r\n');
}
