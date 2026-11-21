import { BarChart3, Cpu, PieChart as PieIcon, ShieldOff } from 'lucide-react';
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { LabTranslations } from '../i18n/labTranslations';
import type { PortScanReport, RiskLevel, TechFingerprint } from '../types/cyber';

interface SeverityChartsProps {
  t: LabTranslations;
  riskCounts?: Record<RiskLevel, number> | null;
  portScan?: PortScanReport | null;
  techStack?: TechFingerprint[] | null;
  excludedCves?: Array<{ cveId: string; reason: string }> | null;
}

const SEVERITY_COLORS: Record<RiskLevel, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#38bdf8',
  Info: '#64748b',
};

export function SeverityCharts({
  t,
  riskCounts,
  portScan,
  techStack,
  excludedCves,
}: SeverityChartsProps) {
  const severityData = [
    { key: 'Critical', name: t.chartsCritical, value: riskCounts?.Critical ?? 0, color: SEVERITY_COLORS.Critical },
    { key: 'High', name: t.chartsHigh, value: riskCounts?.High ?? 0, color: SEVERITY_COLORS.High },
    { key: 'Medium', name: t.chartsMedium, value: riskCounts?.Medium ?? 0, color: SEVERITY_COLORS.Medium },
    { key: 'Low', name: t.chartsLow, value: riskCounts?.Low ?? 0, color: SEVERITY_COLORS.Low },
    { key: 'Info', name: t.chartsInfo, value: riskCounts?.Info ?? 0, color: SEVERITY_COLORS.Info },
  ].filter((item) => item.value > 0);

  const total = severityData.reduce((sum, item) => sum + item.value, 0);

  const portData = (portScan?.openPorts ?? []).map((item) => ({
    name: `${item.port}`,
    latency: item.latencyMs ?? 0,
    service: item.service,
  }));

  return (
    <section aria-label={t.chartsTitle} className="soc-panel rounded-xl p-4 space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <PieIcon className="w-4 h-4 text-fuchsia-400" aria-hidden="true" />
          <h2 className="text-sm font-bold text-slate-50">{t.chartsTitle}</h2>
        </div>
        <p className="text-[11px] text-slate-500 mt-0.5">{t.chartsSubtitle}</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="rounded-lg bg-[#06090F] border border-slate-800 p-2">
          <div className="text-[11px] font-semibold text-slate-300 mb-1 px-1">{t.chartsSeverity}</div>
          {total === 0 ? (
            <div className="h-44 grid place-items-center text-[11px] text-slate-500">{t.chartsNoData}</div>
          ) : (
            <div className="relative h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={44}
                    outerRadius={66}
                    paddingAngle={2}
                    stroke="#06090F"
                    strokeWidth={2}
                  >
                    {severityData.map((item) => (
                      <Cell key={item.key} fill={item.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#0B101B',
                      border: '1px solid #334155',
                      borderRadius: 8,
                      fontSize: 11,
                      color: '#e2e8f0',
                    }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 grid place-items-center pointer-events-none">
                <div className="text-center">
                  <div className="text-xl font-bold font-mono text-slate-100">{total}</div>
                  <div className="text-[9px] uppercase tracking-wide text-slate-500">findings</div>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="rounded-lg bg-[#06090F] border border-slate-800 p-2">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-300 mb-1 px-1">
            <BarChart3 className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
            {t.chartsOpenPorts}
          </div>
          {portData.length === 0 ? (
            <div className="h-44 grid place-items-center text-[11px] text-slate-500">{t.chartsPortsEmpty}</div>
          ) : (
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={portData} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      background: '#0B101B',
                      border: '1px solid #334155',
                      borderRadius: 8,
                      fontSize: 11,
                      color: '#e2e8f0',
                    }}
                    formatter={(value) => [`${Number(value ?? 0)} ms`, 'latency']}
                  />
                  <Bar dataKey="latency" radius={[3, 3, 0, 0]} fill="#22d3ee" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
        <div className="rounded-lg bg-[#06090F] border border-slate-800 p-3">
          <div className="flex items-center gap-1.5 font-semibold text-slate-300 mb-1.5">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
            {t.stackTitle}
          </div>
          {techStack && techStack.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {techStack.map((item) => (
                <span
                  key={`${item.name}-${item.category}`}
                  className="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-200"
                  title={item.evidence}
                >
                  {item.name} · {item.category}
                </span>
              ))}
            </div>
          ) : (
            <div className="text-slate-500">{t.stackEmpty}</div>
          )}
        </div>

        <div className="rounded-lg bg-[#06090F] border border-slate-800 p-3">
          <div className="flex items-center gap-1.5 font-semibold text-slate-300 mb-1.5">
            <ShieldOff className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
            {t.excludedTitle}
          </div>
          {excludedCves && excludedCves.length > 0 ? (
            <ul className="space-y-1">
              {excludedCves.slice(0, 4).map((item) => (
                <li key={item.cveId} className="text-amber-200/90">
                  <span className="font-mono">{item.cveId}</span> — {item.reason}
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-slate-500">{t.excludedEmpty}</div>
          )}
        </div>
      </div>
    </section>
  );
}
