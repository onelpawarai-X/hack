import { ShieldAlert } from 'lucide-react';
import type { LabTranslations } from '../i18n/labTranslations';

interface EthicalBannerProps {
  t: LabTranslations;
}

export function EthicalBanner({ t }: EthicalBannerProps) {
  return (
    <div
      role="note"
      className="rounded-xl border border-amber-500/35 bg-amber-950/25 px-4 py-3 flex items-start gap-3"
    >
      <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
      <div className="text-xs leading-relaxed">
        <div className="font-semibold text-amber-200">{t.disclaimerTitle}</div>
        <p className="text-amber-100/80 mt-0.5">{t.disclaimerBody}</p>
      </div>
    </div>
  );
}
