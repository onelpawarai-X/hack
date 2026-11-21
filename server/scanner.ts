import type { ScanModuleId, ScanProgressEvent, TargetScanResult } from '../src/types/cyber.ts';
import { traceAttackerIp } from './ipAttribution.ts';
import { runModularScanOrchestrator } from './orchestrator.ts';

export { traceAttackerIp };

export async function scanTargetOrWeb(
  rawInput: string,
  modules?: ScanModuleId[],
  onProgress?: (event: ScanProgressEvent) => void,
): Promise<TargetScanResult> {
  return runModularScanOrchestrator({
    target: rawInput,
    modules,
    onProgress,
  });
}
