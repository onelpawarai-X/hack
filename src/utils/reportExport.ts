import type { Language, TargetScanResult } from '../types/cyber';

function safeName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'target';
}

function latin(value: string | number | undefined): string {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '?');
}

function download(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function downloadScanJson(result: TargetScanResult, lang: Language): void {
  const payload = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    language: lang,
    generator: 'SentinelGlobe',
    report: result,
  };
  download(
    new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
    `sentinelglobe-${safeName(result.normalizedTarget)}-${Date.now()}.json`,
  );
}

export async function downloadScanPdf(result: TargetScanResult): Promise<void> {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 42;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const ensure = (height: number) => {
    if (y + height > pageHeight - margin) {
      doc.addPage();
      y = margin;
    }
  };

  const line = (
    text: string,
    size = 9,
    options: { bold?: boolean; color?: [number, number, number]; gap?: number } = {},
  ) => {
    doc.setFont('helvetica', options.bold ? 'bold' : 'normal');
    doc.setFontSize(size);
    doc.setTextColor(...(options.color ?? [30, 41, 59]));
    const lines = doc.splitTextToSize(latin(text), contentWidth) as string[];
    for (const entry of lines) {
      ensure(size * 1.35);
      doc.text(entry, margin, y);
      y += size * 1.35;
    }
    y += options.gap ?? 0;
  };

  const section = (title: string) => {
    ensure(30);
    y += 6;
    doc.setDrawColor(203, 213, 225);
    doc.line(margin, y, pageWidth - margin, y);
    y += 14;
    line(title, 12, { bold: true, color: [15, 23, 42] });
  };

  doc.setFillColor(6, 9, 15);
  doc.rect(0, 0, pageWidth, 92, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(248, 250, 252);
  doc.text('SentinelGlobe', margin, 38);
  doc.setFontSize(10);
  doc.setTextColor(103, 232, 249);
  doc.text('Cyber Threat Radar & Target Security Assessment', margin, 56);
  doc.setTextColor(148, 163, 184);
  doc.text(`Generated ${new Date().toISOString()}`, margin, 73);
  y = 112;

  line(`Target: ${result.normalizedTarget}`, 13, { bold: true, color: [15, 23, 42] });
  line(`Type: ${result.targetType.toUpperCase()}   Scanned: ${result.scannedAt}`, 9, {
    color: [71, 85, 105],
  });
  line(`Verdict: ${result.verdict}`, 12, {
    bold: true,
    color:
      result.verdict === 'CRITICAL'
        ? [185, 28, 28]
        : result.verdict === 'HIGH'
          ? [194, 65, 12]
          : result.verdict === 'ELEVATED'
            ? [180, 83, 9]
            : [4, 120, 87],
  });
  if (result.riskScore) {
    line(
      `Risk score: ${result.riskScore.score}/100   Grade: ${result.riskScore.grade}   Verdict floor: ${result.riskScore.verdictFloor}`,
      10,
      { bold: true, color: [15, 23, 42] },
    );
    const components = result.riskScore.components
      .map((item) => `${item.severity} x${item.count} = ${item.points}`)
      .join(' | ');
    if (components) line(components, 9, { color: [71, 85, 105] });
  }
  line(
    result.ownershipVerified
      ? 'Ownership: domain ownership verified; active probes allowed.'
      : 'Ownership: not verified; active probes were skipped.',
    9,
    { color: [71, 85, 105] },
  );

  if (result.verdictReasons.length > 0) {
    section('Verdict Reasons');
    result.verdictReasons.forEach((reason, index) => line(`${index + 1}. ${reason}`, 9));
  }

  if (result.findings && result.findings.length > 0) {
    section(`Security Findings (${result.findings.length})`);
    result.findings.forEach((finding, index) => {
      line(`${index + 1}. [${finding.riskLevel}] ${finding.title}`, 10, {
        bold: true,
        color: [15, 23, 42],
      });
      line(
        `${finding.owaspId}${finding.cwe ? ` / ${finding.cwe}` : ''} - ${finding.description}`,
        9,
      );
      if (finding.evidence) line(`Evidence: ${finding.evidence.slice(0, 600)}`, 8, { color: [71, 85, 105] });
      line(`Remediation: ${finding.remediation}`, 8, { color: [4, 120, 87] });
      y += 4;
    });
  }

  if (result.cveDetails && result.cveDetails.length > 0) {
    section(`CVE Details (${result.cveDetails.length})`);
    result.cveDetails.forEach((cve) => {
      line(`${cve.cveId}${cve.cvssScore !== undefined ? ` - CVSS ${cve.cvssScore}` : ''}`, 10, {
        bold: true,
        color: [15, 23, 42],
      });
      line(cve.title, 9);
      if (cve.stackMatch) line(`Stack match: ${cve.stackMatch.confidence} - ${cve.stackMatch.reason}`, 8, { color: [3, 105, 161] });
      if (cve.affectedProducts.length > 0) {
        line(`Affected: ${cve.affectedProducts.slice(0, 8).join(' | ')}`, 8, { color: [71, 85, 105] });
      }
      y += 3;
    });
  }

  if (result.techStack && result.techStack.length > 0) {
    section('Detected Technology Stack');
    result.techStack.forEach((item) => {
      line(
        `${item.name}${item.version ? ` ${item.version}` : ''} - ${item.category} - ${item.confidence}${item.cpe ? ` - CPE ${item.cpe}` : ''}`,
        9,
      );
    });
  }

  if (result.executedModules || result.skippedActiveModules) {
    section('Scan Coverage');
    line(`Completed modules: ${(result.executedModules ?? []).join(', ') || 'none'}`, 9);
    if (result.skippedActiveModules && result.skippedActiveModules.length > 0) {
      result.skippedActiveModules.forEach((item) => {
        line(`Skipped ${item.moduleId}: ${item.reason}`, 8, { color: [180, 83, 9] });
      });
    } else {
      line('No active modules were skipped.', 9, { color: [4, 120, 87] });
    }
  }

  section('Technical Details');
  line(`DNS A: ${result.dns.a.join(', ') || '-'}`, 8);
  line(`DNS AAAA: ${result.dns.aaaa.join(', ') || '-'}`, 8);
  line(`NS: ${result.dns.ns.join(', ') || '-'}`, 8);
  line(`MX: ${result.dns.mx.join(', ') || '-'}`, 8);
  line(`Email security: ${result.dns.emailSecurityStatus}`, 8);
  if (result.tls) {
    line(
      `TLS: ${result.tls.valid ? 'valid' : 'invalid'}${result.tls.protocol ? ` / ${result.tls.protocol}` : ''}${result.tls.cipher ? ` / ${result.tls.cipher}` : ''}${result.tls.issuer ? ` / issuer ${result.tls.issuer}` : ''}`,
      8,
    );
  }
  if (result.httpAudit) {
    line(
      `HTTP: ${result.httpAudit.status ?? '-'} / server ${result.httpAudit.server ?? '-'} / missing headers ${result.httpAudit.missingSecurityHeaders.length}`,
      8,
    );
  }
  if (result.portScan) {
    line(
      `Open ports: ${result.portScan.openPorts.map((port) => `${port.port}/${port.service}`).join(', ') || '-'}`,
      8,
    );
  }
  if (result.attribution.length > 0) {
    result.attribution.forEach((node) => {
      line(
        `IP ${node.ip}: ${node.city}, ${node.country} / ${node.asn} / ${node.isp}`,
        8,
        { color: [71, 85, 105] },
      );
    });
  }

  section('Legal');
  line(
    result.legalDisclaimer ??
      'Authorized security assessment only. Active probes require verified domain ownership.',
    8,
    { color: [100, 116, 139] },
  );

  const pages = doc.getNumberOfPages();
  for (let page = 1; page <= pages; page += 1) {
    doc.setPage(page);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(`SentinelGlobe - page ${page} of ${pages}`, margin, pageHeight - 20);
  }

  doc.save(`sentinelglobe-${safeName(result.normalizedTarget)}-${Date.now()}.pdf`);
}
