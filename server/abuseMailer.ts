import { randomUUID } from 'node:crypto';
import type { AttackerDossier } from './attackerDossier.ts';
import { buildAttackerDossier } from './attackerDossier.ts';
import nodemailer from 'nodemailer';
import type { BlockedIpEntry } from '../src/types/cyber.ts';
import { attackSensor } from './attackSensor.ts';
import { deleteConfig, getConfig, insertDelivery, setConfig } from './db.ts';
import { lookupRdapIpAbuse } from './defenseEngine.ts';

interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user?: string;
  pass?: string;
  from: string;
}

function smtpConfig(): SmtpConfig | null {
  const host = getConfig('smtp.host') ?? process.env.SMTP_HOST?.trim();
  const from = getConfig('smtp.from') ?? process.env.SMTP_FROM?.trim();
  if (!host || !from) return null;
  const portRaw = getConfig('smtp.port') ?? process.env.SMTP_PORT ?? '587';
  const port = Number(portRaw) || 587;
  const secureRaw = getConfig('smtp.secure') ?? process.env.SMTP_SECURE ?? 'false';
  return {
    host,
    port,
    secure: secureRaw === 'true' || port === 465,
    user: getConfig('smtp.user') ?? process.env.SMTP_USER?.trim() ?? undefined,
    pass: getConfig('smtp.pass') ?? process.env.SMTP_PASS?.trim() ?? undefined,
    from,
  };
}

export function getSmtpStatus(): {
  configured: boolean;
  host?: string;
  port?: number;
  secure?: boolean;
  from?: string;
  source: 'database' | 'environment' | 'none';
  autoSend: boolean;
  detail: string;
} {
  const config = smtpConfig();
  return {
    configured: Boolean(config),
    host: config?.host,
    port: config?.port,
    secure: config?.secure,
    from: config?.from,
    source: getConfig('smtp.host') ? 'database' : config ? 'environment' : 'none',
    autoSend: getConfig('smtp.autoSend') === 'true',
    detail: config
      ? `SMTP ready via ${config.host}:${config.port}${config.secure ? ' (TLS)' : ''}`
      : 'Set SMTP_HOST and SMTP_FROM, or save SMTP settings here',
  };
}

export function setSmtpConfig(payload: Record<string, unknown>): { ok: boolean; error?: string } {
  const host = String(payload.host ?? '').trim();
  const from = String(payload.from ?? '').trim();
  if (!host || !from) return { ok: false, error: 'SMTP host and from address are required.' };
  const port = Number(payload.port ?? 587);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return { ok: false, error: 'SMTP port is invalid.' };
  }
  setConfig('smtp.host', host);
  setConfig('smtp.port', String(port));
  setConfig('smtp.secure', String(Boolean(payload.secure)));
  setConfig('smtp.from', from);
  if (payload.user) setConfig('smtp.user', String(payload.user));
  if (payload.pass) setConfig('smtp.pass', String(payload.pass));
  if (typeof payload.autoSend === 'boolean') setConfig('smtp.autoSend', String(payload.autoSend));
  return { ok: true };
}

export function clearSmtpConfig(): void {
  for (const key of ['smtp.host', 'smtp.port', 'smtp.secure', 'smtp.from', 'smtp.user', 'smtp.pass']) {
    deleteConfig(key);
  }
}

function logMail(to: string, status: string, detail: string, ip?: string) {
  try {
    insertDelivery({
      id: randomUUID(),
      ts: new Date().toISOString(),
      channel: 'smtp',
      target: to,
      status,
      detail: detail.slice(0, 600),
      eventId: ip,
    });
  } catch {
    // best effort
  }
}

export async function sendAbuseEmail(input: {
  to: string[];
  subject: string;
  text: string;
  ip?: string;
}): Promise<{ ok: boolean; detail: string; accepted: string[] }> {
  const config = smtpConfig();
  if (!config) {
    return { ok: false, detail: 'SMTP is not configured.', accepted: [] };
  }
  const recipients = input.to.map((value) => value.trim()).filter(Boolean);
  if (recipients.length === 0) {
    return { ok: false, detail: 'No recipient address was provided.', accepted: [] };
  }

  try {
    const transport = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.user && config.pass ? { user: config.user, pass: config.pass } : undefined,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });
    const info = await transport.sendMail({
      from: config.from,
      to: recipients.join(', '),
      subject: input.subject,
      text: input.text,
      headers: { 'X-SentinelGlobe': 'abuse-report' },
    });
    const accepted = Array.isArray(info.accepted) ? info.accepted.map(String) : recipients;
    logMail(recipients.join(', '), 'sent', `Message ${info.messageId}`, input.ip);
    return { ok: true, detail: `Sent via ${config.host} (${info.messageId})`, accepted };
  } catch (err) {
    const detail = err instanceof Error ? err.message : 'SMTP delivery failed';
    logMail(recipients.join(', '), 'failed', detail, input.ip);
    return { ok: false, detail, accepted: [] };
  }
}

export async function sendAbuseReportForIp(
  ip: string,
  overrideRecipients?: string[],
): Promise<{ ok: boolean; detail: string; recipients: string[] }> {
  const report = await attackSensor.buildAbuseReport(ip);
  let recipients = (overrideRecipients ?? []).filter(Boolean);
  if (recipients.length === 0) {
    const rdap = await lookupRdapIpAbuse(ip);
    recipients = rdap.abuseEmails;
  }
  if (recipients.length === 0) {
    return {
      ok: false,
      detail: 'No abuse contact is published for this IP. Enter a recipient manually.',
      recipients: [],
    };
  }
  const result = await sendAbuseEmail({
    to: recipients,
    subject: `Abuse report: malicious traffic from ${ip}`,
    text: report.report,
    ip,
  });
  return { ok: result.ok, detail: result.detail, recipients };
}

export async function testSmtp(to: string): Promise<{ ok: boolean; detail: string }> {
  const result = await sendAbuseEmail({
    to: [to],
    subject: 'SentinelGlobe SMTP test',
    text: 'This is a synthetic SMTP configuration test from SentinelGlobe. No attack occurred.',
  });
  return { ok: result.ok, detail: result.detail };
}

export async function maybeAutoSendAbuseReport(entry: BlockedIpEntry): Promise<void> {
  if (getConfig('smtp.autoSend') !== 'true') return;
  if (!entry.abuseEmails || entry.abuseEmails.length === 0) return;
  await sendAbuseEmail({
    to: entry.abuseEmails,
    subject: `Abuse report: malicious traffic from ${entry.ip}`,
    text: [
      'SentinelGlobe — Automated Abuse Report',
      `Generated: ${new Date().toISOString()}`,
      `Attacker IP: ${entry.ip}`,
      `ASN / ISP: ${entry.asn ?? 'unknown'} / ${entry.isp ?? 'unknown'}`,
      `Reason: ${entry.reason}`,
      `Severity: ${entry.severity}`,
      `Firewall rule: ${entry.firewallRules.iptables}`,
      '',
      'This message was sent automatically because the source triggered active defense.',
    ].join('\n'),
    ip: entry.ip,
  }).catch(() => null);
}


export function isGmailSmtp(): boolean {
  const config = smtpConfig();
  return Boolean(config && /smtp\.gmail\.com$/i.test(config.host));
}

export async function sendForensicDossierEmail(
  dossier: AttackerDossier,
  recipients: string[],
): Promise<{ ok: boolean; detail: string; accepted: string[] }> {
  const config = smtpConfig();
  if (!config) return { ok: false, detail: 'SMTP/Gmail is not configured.', accepted: [] };
  const to = recipients.map((value) => value.trim()).filter(Boolean);
  if (to.length === 0) return { ok: false, detail: 'No recipient address was provided.', accepted: [] };
  try {
    const transport = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.user && config.pass ? { user: config.user, pass: config.pass } : undefined,
      connectionTimeout: 12_000,
      greetingTimeout: 12_000,
      socketTimeout: 30_000,
    });
    const info = await transport.sendMail({
      from: config.from,
      to: to.join(', '),
      subject: `[SentinelGlobe] Forensic dossier — attacker ${dossier.ip} (${dossier.risk.severity})`,
      text: dossier.reportText,
      html: dossier.reportHtml,
      attachments: [
        {
          filename: `sentinel-dossier-${dossier.ip}.json`,
          content: JSON.stringify(dossier, null, 2),
          contentType: 'application/json',
        },
        {
          filename: `sentinel-dossier-${dossier.ip}.txt`,
          content: dossier.reportText,
          contentType: 'text/plain',
        },
      ],
      headers: {
        'X-SentinelGlobe': 'forensic-dossier',
        'X-SentinelGlobe-Evidence-SHA256': dossier.forensic.sha256,
      },
    });
    logMail(to.join(', '), 'sent', `Dossier ${info.messageId}`, dossier.ip);
    return {
      ok: true,
      detail: `Sent via ${config.host} (${info.messageId})`,
      accepted: Array.isArray(info.accepted) ? info.accepted.map(String) : to,
    };
  } catch (err) {
    const detail = err instanceof Error ? err.message : 'SMTP delivery failed';
    logMail(to.join(', '), 'failed', detail, dossier.ip);
    return { ok: false, detail, accepted: [] };
  }
}

export async function sendForensicDossierForIp(
  ip: string,
  recipients?: string[],
): Promise<{ ok: boolean; detail: string; recipients: string[]; dossier: AttackerDossier }> {
  const dossier = await buildAttackerDossier(ip);
  const to = (recipients ?? []).filter(Boolean);
  const finalRecipients = to.length > 0 ? to : dossier.whois.abuseEmails;
  if (finalRecipients.length === 0) {
    return {
      ok: false,
      detail: 'No recipient. Enter the affected company or the RIR abuse contact manually.',
      recipients: [],
      dossier,
    };
  }
  const result = await sendForensicDossierEmail(dossier, finalRecipients);
  return { ...result, recipients: finalRecipients, dossier };
}

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
