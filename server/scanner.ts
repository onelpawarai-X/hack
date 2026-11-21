import type { ScanModuleId, ScanProgressEvent, TargetScanResult } from '../src/types/cyber.ts';
import type { ScanLogEvent } from '../src/types/realtime.ts';
import { applyRiskScore } from './findingsBuilder.ts';
import { traceAttackerIp } from './ipAttribution.ts';
import { runModularScanOrchestrator } from './orchestrator.ts';

export { traceAttackerIp };

export async function scanTargetOrWeb(
  rawInput: string,
  modules?: ScanModuleId[],
  onProgress?: (event: ScanProgressEvent) => void,
  onLog?: (event: ScanLogEvent) => void,
): Promise<TargetScanResult> {
  const result = await runModularScanOrchestrator({
    target: rawInput,
    modules,
    onProgress,
    onLog,
  });
  return applyRiskScore(result);
}
