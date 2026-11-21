import {
  AlertTriangle,
  Camera,
  Cpu,
  Crosshair,
  ExternalLink,
  FileImage,
  Hash,
  Loader2,
  MapPin,
  Search,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import { useEffect, useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import type { CyberTranslations } from '../i18n/cyberTranslations';
import type { ImageForensicsResult, Language, ThreatNode } from '../types/cyber';
import { formatUtcTimestamp } from '../utils/formatters';

interface ImageForensicsPanelProps {
  t: CyberTranslations;
  lang: Language;
  onPinNodeOnMap: (node: ThreatNode) => void;
  onDefendIp: (ip: string, reason?: string) => void;
}

export function ImageForensicsPanel({
  t,
  lang,
  onPinNodeOnMap,
  onDefendIp,
}: ImageForensicsPanelProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImageForensicsResult | null>(null);
  const [tagFilter, setTagFilter] = useState('');

  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const processFile = async (file: File) => {
    if (file.size > 15 * 1024 * 1024) {
      setError('File exceeds 15 MB limit.');
      return;
    }

    setError(null);
    setLoading(true);
    setTagFilter('');
    setPreviewError(false);

    const nextPreview = URL.createObjectURL(file);
    setPreviewUrl((prev) => {
      if (prev) URL.revokeObjectURL(prev);
      return nextPreview;
    });

    try {
      const base64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result ?? ''));
        reader.onerror = () => reject(new Error('Failed to read image file'));
        reader.readAsDataURL(file);
      });

      const res = await fetch('/api/forensics/image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: file.name,
          mimeType: file.type || 'application/octet-stream',
          base64,
        }),
      });
      const json = (await res.json()) as ImageForensicsResult & {
        error?: string;
        details?: string;
      };
      if (!res.ok) {
        throw new Error(json.details || json.error || 'Forensics extraction failed');
      }
      setResult(json);
      if (json.gps?.mapNode) {
        onPinNodeOnMap(json.gps.mapNode);
      } else if (json.embeddedIpTraces.length > 0) {
        onPinNodeOnMap(json.embeddedIpTraces[0]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to analyze picture');
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void processFile(file);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) void processFile(file);
  };

  const filteredTags = (result?.rawTags ?? []).filter((tag) => {
    const q = tagFilter.trim().toLowerCase();
    if (!q) return true;
    return (
      tag.group.toLowerCase().includes(q) ||
      tag.key.toLowerCase().includes(q) ||
      tag.value.toLowerCase().includes(q)
    );
  });

  const hasCameraInfo = Boolean(
    result &&
      (result.camera.make ||
        result.camera.model ||
        result.camera.hostComputer ||
        result.camera.software ||
        result.camera.dateTimeOriginal ||
        result.camera.lens ||
        result.camera.serialNumber ||
        result.camera.bodySerialNumber ||
        result.camera.ownerName ||
        result.camera.artist),
  );

  const hasEmbedded = Boolean(
    result &&
      (result.embeddedStrings.urls.length > 0 ||
        result.embeddedStrings.domains.length > 0 ||
        result.embeddedStrings.ips.length > 0 ||
        result.embeddedStrings.ipv6s.length > 0 ||
        result.embeddedStrings.emails.length > 0 ||
        result.embeddedStrings.filePaths.length > 0 ||
        result.embeddedStrings.suspiciousTokens.length > 0),
  );

  return (
    <section aria-label={t.forensics.title} className="soc-panel rounded-xl p-5 sm:p-6 space-y-5">
      <div>
        <h2 className="text-lg font-bold text-slate-50 flex items-center gap-2">
          <FileImage className="w-5 h-5 text-sky-400 shrink-0" aria-hidden="true" />
          <span>{t.forensics.title}</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-4xl">{t.forensics.subtitle}</p>
      </div>

      {/* Dropzone */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className="rounded-xl border border-dashed border-slate-700 hover:border-sky-400/60 bg-[#05070B]/70 p-6 flex flex-col sm:flex-row items-center justify-between gap-4 transition-colors"
      >
        <div className="space-y-1 text-center sm:text-left">
          <div className="text-sm font-semibold text-slate-100">
            {t.forensics.dropzoneTitle}
          </div>
          <div className="text-xs text-slate-400">{t.forensics.dropzoneHint}</div>
        </div>

        <div>
          <label htmlFor="image-forensics-upload" className="sr-only">
            {t.forensics.selectFileBtn}
          </label>
          <input
            ref={fileInputRef}
            id="image-forensics-upload"
            type="file"
            accept="image/*,.heic,.tif,.tiff"
            onChange={handleFileChange}
            className="hidden"
          />
          <button
            type="button"
            disabled={loading}
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer"
          >
            {loading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Upload className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            <span>{loading ? t.forensics.analyzingBtn : t.forensics.selectFileBtn}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/50 border border-red-500/40 text-xs text-red-200">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-5 pt-2 border-t border-slate-800/80">
          {/* Forensic Alert Banner */}
          {result.polyglotWarnings.length > 0 && (
            <div className="p-4 rounded-xl bg-red-950/55 border border-red-500/50 text-xs text-red-200 space-y-1.5">
              <div className="font-bold text-red-400 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                <span>
                  {result.mimeMismatch
                    ? t.forensics.mimeMismatchWarn
                    : t.forensics.anomalyWarnTitle}
                </span>
              </div>
              {result.polyglotWarnings.map((w, idx) => (
                <div key={idx}>• {w}</div>
              ))}
            </div>
          )}

          {/* Honest Forensic Summary Note */}
          <div className="p-3.5 rounded-lg bg-slate-950/75 border border-slate-800 text-xs space-y-1">
            <div className="font-semibold text-sky-300">{t.forensics.originNoteTitle}</div>
            <p className="text-slate-300 leading-relaxed">{result.privacyAndOriginNote}</p>
          </div>

          {/* Preview + Embedded EXIF Thumbnail + Container Pipeline + Cryptographic Hashes */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 text-xs">
            <div className="lg:col-span-5 flex items-start gap-4">
              <div className="flex flex-col gap-2 shrink-0">
                {previewUrl && !previewError ? (
                  <img
                    src={previewUrl}
                    alt={result.filename}
                    referrerPolicy="no-referrer"
                    onError={() => setPreviewError(true)}
                    className="w-24 h-24 object-cover rounded-lg border border-slate-700 bg-[#06090F]"
                  />
                ) : (
                  <div className="w-24 h-24 rounded-lg border border-slate-700/80 bg-[#06090F] flex flex-col items-center justify-center gap-1.5 px-2 text-center">
                    <FileImage className="w-6 h-6 text-sky-400" aria-hidden="true" />
                    <span className="font-mono text-[10px] text-slate-300 truncate max-w-full">
                      {result.detectedFormat}
                    </span>
                  </div>
                )}
                {result.embeddedThumbnailDataUrl && (
                  <div className="space-y-1">
                    <div className="text-[10px] text-amber-300 font-medium">
                      {t.forensics.thumbnailTitle}
                    </div>
                    <img
                      src={result.embeddedThumbnailDataUrl}
                      alt="Embedded EXIF thumbnail"
                      className="w-24 h-16 object-cover rounded border border-amber-500/50 bg-slate-950"
                    />
                  </div>
                )}
              </div>

              <div className="min-w-0 space-y-1.5">
                <div className="text-sm font-bold font-mono text-white break-all">
                  {result.filename}
                </div>
                <div className="text-slate-300">
                  {t.forensics.formatLabel}:{' '}
                  <span className="font-mono font-semibold text-sky-300">
                    {result.detectedFormat}
                  </span>
                </div>
                <div className="font-mono tabular-nums text-slate-400">
                  {t.forensics.fileSizeLabel}: {(result.fileSizeBytes / 1024).toFixed(1)} KB
                  {result.dimensions.width && result.dimensions.height
                    ? ` · ${result.dimensions.width}×${result.dimensions.height}px`
                    : ''}
                </div>
                <div className="font-mono tabular-nums text-slate-400">
                  {t.forensics.entropyLabel}: {result.entropyBitsPerByte} / 8.0 bits
                </div>
                <div
                  className={`font-mono tabular-nums ${
                    result.appendedTrailingBytes > 64
                      ? 'text-red-400 font-semibold'
                      : 'text-slate-400'
                  }`}
                >
                  {t.forensics.trailingBytesLabel}: {result.appendedTrailingBytes} bytes
                </div>
                {result.trailingPayloadPreview && (
                  <div className="p-2 rounded bg-red-950/40 border border-red-500/30 font-mono text-[10px] text-red-200 break-all">
                    <span className="text-red-400 font-semibold">
                      {t.forensics.trailingPreviewLabel}:{' '}
                    </span>
                    {result.trailingPayloadPreview}
                  </div>
                )}
                <div className="font-mono tabular-nums text-slate-500">
                  {formatUtcTimestamp(result.analyzedAt, lang)}
                </div>
              </div>
            </div>

            <div className="lg:col-span-7 space-y-3">
              <div className="space-y-1.5">
                <h3 className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Hash className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                  <span>{t.forensics.hashesTitle}</span>
                </h3>
                <div className="p-3 rounded-lg bg-[#05070B] border border-slate-800 font-mono text-[11px] space-y-1 break-all">
                  <div>
                    <span className="text-slate-400">SHA-256: </span>
                    <span className="text-emerald-300">{result.hashes.sha256}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">SHA-1:   </span>
                    <span className="text-slate-200">{result.hashes.sha1}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">MD5:     </span>
                    <span className="text-slate-200">{result.hashes.md5}</span>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#05070B] border border-slate-800 space-y-1.5">
                <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
                  <span>{t.forensics.pipelineTitle}</span>
                </div>
                <div className="text-sky-300 font-medium">
                  {result.containerAnalysis.pipelineClass}
                </div>
                {result.containerAnalysis.recompressionSignals.map((sig, i) => (
                  <div key={i} className="text-slate-300">
                    • {sig}
                  </div>
                ))}
                {result.containerAnalysis.markersOrChunks.length > 0 && (
                  <div className="font-mono text-[10px] text-slate-400 break-all">
                    Markers/Chunks: {result.containerAnalysis.markersOrChunks.join(' → ')}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* 3-Column Deep Device, GPS Address & Embedded Artifacts */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 text-xs pt-3 border-t border-slate-800/70">
            {/* Phone / Camera Hardware Fingerprint */}
            <div className="space-y-2">
              <h3 className="font-semibold text-slate-200 flex items-center gap-1.5">
                <Camera className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                <span>{t.forensics.cameraTitle}</span>
              </h3>
              {hasCameraInfo ? (
                <dl className="space-y-1.5 text-slate-300">
                  {(result.camera.make || result.camera.model) && (
                    <div>
                      Device:{' '}
                      <span className="text-white font-medium">
                        {[result.camera.make, result.camera.model].filter(Boolean).join(' ')}
                      </span>
                    </div>
                  )}
                  {result.camera.hostComputer && (
                    <div>
                      Host OS / Phone:{' '}
                      <span className="font-mono text-sky-300">{result.camera.hostComputer}</span>
                    </div>
                  )}
                  {(result.camera.lensMake || result.camera.lens) && (
                    <div>
                      Lens: {[result.camera.lensMake, result.camera.lens].filter(Boolean).join(' ')}
                    </div>
                  )}
                  {(result.camera.serialNumber || result.camera.bodySerialNumber) && (
                    <div className="font-mono text-amber-300">
                      Serial: {result.camera.serialNumber || result.camera.bodySerialNumber}
                    </div>
                  )}
                  {result.camera.imageUniqueId && (
                    <div className="font-mono text-slate-400 break-all">
                      ImageID: {result.camera.imageUniqueId}
                    </div>
                  )}
                  {result.camera.software && (
                    <div>
                      Software: <span className="font-mono text-sky-300">{result.camera.software}</span>
                    </div>
                  )}
                  {(result.camera.ownerName || result.camera.artist) && (
                    <div>
                      Owner / Author: {result.camera.ownerName || result.camera.artist}
                    </div>
                  )}
                  {result.camera.copyright && <div>Copyright: {result.camera.copyright}</div>}
                  {result.camera.dateTimeOriginal && (
                    <div className="font-mono">Captured: {result.camera.dateTimeOriginal}</div>
                  )}
                  {result.camera.modifyDate && (
                    <div className="font-mono">Modified: {result.camera.modifyDate}</div>
                  )}
                  {(result.camera.iso ||
                    result.camera.fNumber ||
                    result.camera.exposureTime ||
                    result.camera.focalLength) && (
                    <div className="font-mono text-slate-400">
                      {[
                        result.camera.focalLength,
                        result.camera.fNumber ? `f/${result.camera.fNumber}` : null,
                        result.camera.exposureTime,
                        result.camera.iso ? `ISO ${result.camera.iso}` : null,
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </div>
                  )}
                </dl>
              ) : (
                <p className="text-slate-400 leading-relaxed">{t.forensics.noExifFound}</p>
              )}
            </div>

            {/* Hyper-Detailed GPS & Physical Location */}
            <div className="space-y-2">
              <h3 className="font-semibold text-slate-200 flex items-center gap-1.5">
                <MapPin className="w-3.5 h-3.5 text-red-400" aria-hidden="true" />
                <span>{t.forensics.gpsTitle}</span>
              </h3>
              {result.gps ? (
                <div className="space-y-2">
                  <div className="font-mono tabular-nums text-sky-300 font-semibold">
                    {result.gps.latitude.toFixed(6)}, {result.gps.longitude.toFixed(6)}
                    {typeof result.gps.altitude === 'number'
                      ? ` · ${result.gps.altitude}m alt`
                      : ''}
                    {typeof result.gps.compassHeading === 'number'
                      ? ` · ${result.gps.compassHeading}°`
                      : ''}
                  </div>
                  {result.gps.gpsMethod && (
                    <div className="font-mono text-[11px] text-slate-400">
                      Method: {result.gps.gpsMethod}
                    </div>
                  )}
                  {result.gps.physicalAddress && (
                    <div className="text-slate-100 leading-relaxed">
                      {result.gps.physicalAddress}
                    </div>
                  )}
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {result.gps.mapNode && (
                      <button
                        type="button"
                        onClick={() => onPinNodeOnMap(result.gps!.mapNode!)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition-colors cursor-pointer"
                      >
                        <Crosshair className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>{t.forensics.pinGpsOnMapBtn}</span>
                      </button>
                    )}
                    {result.gps.osmUrl && (
                      <a
                        href={result.gps.osmUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-200 text-xs"
                      >
                        <span>{t.forensics.openOsmBtn}</span>
                        <ExternalLink className="w-3 h-3" aria-hidden="true" />
                      </a>
                    )}
                  </div>
                </div>
              ) : result.textualLocation ? (
                <div className="space-y-1 text-slate-200">
                  <div>
                    {[
                      result.textualLocation.sublocation,
                      result.textualLocation.city,
                      result.textualLocation.state,
                      result.textualLocation.country,
                    ]
                      .filter(Boolean)
                      .join(', ')}
                  </div>
                </div>
              ) : (
                <p className="text-slate-400 leading-relaxed">{t.forensics.noGpsFound}</p>
              )}
            </div>

            {/* Embedded IPs, URLs, File Paths, UTF-16 & Tokens */}
            <div className="space-y-2">
              <h3 className="font-semibold text-slate-200">{t.forensics.embeddedTitle}</h3>
              {hasEmbedded ? (
                <div className="space-y-1.5 font-mono text-[11px] break-all">
                  {result.embeddedStrings.suspiciousTokens.length > 0 && (
                    <div className="text-red-400 font-semibold">
                      Tokens: {result.embeddedStrings.suspiciousTokens.join(', ')}
                    </div>
                  )}
                  {result.embeddedStrings.ips.length > 0 && (
                    <div className="text-red-300">
                      IPv4: {result.embeddedStrings.ips.join(', ')}
                    </div>
                  )}
                  {result.embeddedStrings.ipv6s.length > 0 && (
                    <div className="text-orange-300">
                      IPv6: {result.embeddedStrings.ipv6s.join(', ')}
                    </div>
                  )}
                  {result.embeddedStrings.urls.length > 0 && (
                    <div className="text-amber-300">
                      URLs: {result.embeddedStrings.urls.slice(0, 4).join(' · ')}
                    </div>
                  )}
                  {result.embeddedStrings.domains.length > 0 && (
                    <div className="text-sky-300">
                      Domains: {result.embeddedStrings.domains.slice(0, 5).join(', ')}
                    </div>
                  )}
                  {result.embeddedStrings.filePaths.length > 0 && (
                    <div className="text-purple-300">
                      Paths: {result.embeddedStrings.filePaths.slice(0, 3).join(' · ')}
                    </div>
                  )}
                  {result.embeddedStrings.emails.length > 0 && (
                    <div className="text-slate-300">
                      Emails: {result.embeddedStrings.emails.join(', ')}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-emerald-300/90 leading-relaxed">
                  {t.forensics.noEmbeddedStrings}
                </p>
              )}
            </div>
          </div>

          {/* Auto-Traced Public IPs Extracted From Inside Image */}
          {result.embeddedIpTraces.length > 0 && (
            <div className="pt-3 border-t border-slate-800/70 space-y-2.5">
              <h3 className="text-xs font-semibold text-red-300">
                {t.forensics.embeddedIpsTitle} ({result.embeddedIpTraces.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                {result.embeddedIpTraces.map((trace) => (
                  <div
                    key={trace.id}
                    className="p-3.5 rounded-lg bg-[#05070B] border border-red-500/35 space-y-1.5"
                  >
                    <div className="font-mono font-bold text-white">{trace.ip}</div>
                    <div className="text-slate-200">
                      {trace.city}, {trace.country} ({trace.countryCode})
                    </div>
                    {trace.physicalAddress && (
                      <div className="text-slate-400 line-clamp-2">{trace.physicalAddress}</div>
                    )}
                    <div className="font-mono text-[11px] text-slate-400">
                      {trace.asn} · {trace.isp}
                    </div>
                    <div className="flex flex-wrap gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => onPinNodeOnMap(trace)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-semibold cursor-pointer"
                      >
                        <Crosshair className="w-3 h-3" aria-hidden="true" />
                        <span>{t.scanner.focusOnMapBtn}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => onDefendIp(trace.ip, `Extracted from image ${result.filename}`)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-semibold cursor-pointer"
                      >
                        <ShieldCheck className="w-3 h-3" aria-hidden="true" />
                        <span>{t.tables.defendNow}</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Complete Raw Metadata Tags Table */}
          {result.rawTags.length > 0 && (
            <div className="pt-3 border-t border-slate-800/70 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <h3 className="text-xs font-semibold text-slate-200">
                  {t.forensics.rawTagsTitle} ({result.rawTags.length})
                </h3>
                <div className="relative w-full sm:w-64">
                  <label htmlFor="raw-tags-filter" className="sr-only">
                    {t.forensics.filterTagsPlaceholder}
                  </label>
                  <Search
                    className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
                    aria-hidden="true"
                  />
                  <input
                    id="raw-tags-filter"
                    type="text"
                    value={tagFilter}
                    onChange={(e) => setTagFilter(e.target.value)}
                    placeholder={t.forensics.filterTagsPlaceholder}
                    className="w-full pl-8 pr-3 py-1 rounded-md bg-[#05070B] border border-slate-800 focus:border-slate-600 focus:outline-none text-xs text-slate-100 placeholder:text-slate-500"
                  />
                </div>
              </div>

              <div className="max-h-64 overflow-y-auto rounded-lg border border-slate-800/80 bg-[#05070B]">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="sticky top-0 bg-slate-950 border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="py-2 px-3 font-medium">Segment</th>
                      <th className="py-2 px-3 font-medium">Tag</th>
                      <th className="py-2 px-3 font-medium">Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50 font-mono">
                    {filteredTags.map((tag, i) => (
                      <tr key={`${tag.group}-${tag.key}-${i}`} className="hover:bg-slate-900/50">
                        <td className="py-1.5 px-3 text-slate-400 uppercase whitespace-nowrap">
                          {tag.group}
                        </td>
                        <td className="py-1.5 px-3 text-sky-300 whitespace-nowrap">{tag.key}</td>
                        <td className="py-1.5 px-3 text-slate-200 break-all">{tag.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
