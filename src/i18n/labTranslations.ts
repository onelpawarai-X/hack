import type { Language } from '../types/cyber';

export interface LabTranslations {
  disclaimerTitle: string;
  disclaimerBody: string;
  mapTitle: string;
  mapSubtitle: string;
  mapLiveBadge: string;
  mapHeatOn: string;
  mapHeatOff: string;
  mapFocusScan: string;
  mapResetView: string;
  mapScannerOrigin: string;
  mapOriginUnknown: string;
  mapLegendCritical: string;
  mapLegendHigh: string;
  mapLegendClean: string;
  mapLegendScanner: string;
  mapNodesLabel: string;
  mapScanPointsLabel: string;
  mapNoScan: string;
  mapLoading: string;
  terminalTitle: string;
  terminalSubtitle: string;
  terminalEmpty: string;
  terminalClear: string;
  terminalConnected: string;
  terminalDisconnected: string;
  terminalWaiting: string;
  chartsTitle: string;
  chartsSubtitle: string;
  chartsSeverity: string;
  chartsNoData: string;
  chartsCritical: string;
  chartsHigh: string;
  chartsMedium: string;
  chartsLow: string;
  chartsInfo: string;
  chartsOpenPorts: string;
  chartsPortsEmpty: string;
  progressTitle: string;
  progressIdle: string;
  progressScanning: string;
  progressDone: string;
  verifyTitle: string;
  verifySubtitle: string;
  verifyDomainPlaceholder: string;
  verifyCheckBtn: string;
  verifyChecking: string;
  verifyMethodDns: string;
  verifyMethodHttp: string;
  verifyVerified: string;
  verifyPending: string;
  verifyTokenLabel: string;
  verifyTxtHost: string;
  verifyTxtValue: string;
  verifyHttpPath: string;
  verifyHttpContent: string;
  verifyHint: string;
  stackTitle: string;
  stackEmpty: string;
  portsTitle: string;
  portsEmpty: string;
  excludedTitle: string;
  excludedEmpty: string;
  scanNow: string;
  scanningNow: string;
}

const BN: LabTranslations = {
  disclaimerTitle: 'অনুমোদিত নিরাপত্তা পরীক্ষা',
  disclaimerBody:
    'এই টুলটি শুধুমাত্র নিজের বা লিখিত অনুমতি থাকা সিস্টেম পরীক্ষা করার জন্য। গভীর সক্রিয় স্ক্যান চালানোর আগে ডোমেইন মালিকানা যাচাই বাধ্যতামূলক। অননুমোদিত ব্যবহার আইনত নিষিদ্ধ।',
  mapTitle: 'লাইভ হ্যাকিং ল্যাব ম্যাপ',
  mapSubtitle:
    'প্রকৃত ওপেনস্ট্রিটম্যাপ টাইলসে স্ক্যান টার্গেট, রেজলভড আইপি এবং স্ক্যানার নোডের অবস্থান রিয়েল-টাইমে দেখা যায়।',
  mapLiveBadge: 'লাইভ',
  mapHeatOn: 'হিটম্যাপ বন্ধ করুন',
  mapHeatOff: 'হিটম্যাপ চালু করুন',
  mapFocusScan: 'স্ক্যানে ফোকাস',
  mapResetView: 'ভিউ রিসেট',
  mapScannerOrigin: 'স্ক্যানার নোড',
  mapOriginUnknown: 'স্ক্যানার অবস্থান পাওয়া যায়নি',
  mapLegendCritical: 'ক্রিটিক্যাল',
  mapLegendHigh: 'হাই',
  mapLegendClean: 'নিরাপদ',
  mapLegendScanner: 'স্ক্যানার',
  mapNodesLabel: 'থ্রেট নোড',
  mapScanPointsLabel: 'স্ক্যান পয়েন্ট',
  mapNoScan: 'এখনো কোনো স্ক্যান চালানো হয়নি',
  mapLoading: 'ম্যাপ লোড হচ্ছে...',
  terminalTitle: 'লাইভ স্ক্যান টার্মিনাল',
  terminalSubtitle: 'ব্যাকএন্ড স্ক্যানারের প্রতিটি ধাপ সকেট চ্যানেলে সরাসরি স্ট্রিম হয়।',
  terminalEmpty: 'স্ক্যান শুরু করুন — এখানে রিয়েল-টাইম লগ দেখা যাবে।',
  terminalClear: 'ক্লিয়ার',
  terminalConnected: 'সংযুক্ত',
  terminalDisconnected: 'বিচ্ছিন্ন',
  terminalWaiting: 'স্ক্যানের অপেক্ষায়...',
  chartsTitle: 'ভালনারেবিলিটি অ্যানালিটিক্স',
  chartsSubtitle: 'স্ক্যান শেষে ঝুঁকির অনুপাত ও খোলা পোর্টের সারসংক্ষেপ।',
  chartsSeverity: 'ঝুঁকির মাত্রা',
  chartsNoData: 'এখনো কোনো ফলাফল নেই',
  chartsCritical: 'ক্রিটিক্যাল',
  chartsHigh: 'হাই',
  chartsMedium: 'মিডিয়াম',
  chartsLow: 'লো',
  chartsInfo: 'ইনফো',
  chartsOpenPorts: 'খোলা পোর্ট',
  chartsPortsEmpty: 'কোনো খোলা পোর্ট পাওয়া যায়নি',
  progressTitle: 'স্ক্যান প্রোগ্রেস',
  progressIdle: 'স্ক্যান শুরু করুন',
  progressScanning: 'স্ক্যান চলছে',
  progressDone: 'স্ক্যান সম্পন্ন',
  verifyTitle: 'ডোমেইন মালিকানা যাচাই',
  verifySubtitle:
    'সক্রিয় পোর্ট স্ক্যান ও ভলনারেবিলিটি প্রোব চালানোর আগে প্রমাণ করুন যে ডোমেইনটি আপনার।',
  verifyDomainPlaceholder: 'example.com',
  verifyCheckBtn: 'যাচাই করুন',
  verifyChecking: 'যাচাই চলছে...',
  verifyMethodDns: 'ডিএনএস টেক্সট রেকর্ড',
  verifyMethodHttp: 'এইচটিটিপি ফাইল',
  verifyVerified: 'যাচাই সম্পন্ন',
  verifyPending: 'এখনো যাচাই হয়নি',
  verifyTokenLabel: 'টোকেন',
  verifyTxtHost: 'টেক্সট রেকর্ড হোস্ট',
  verifyTxtValue: 'টেক্সট রেকর্ড মান',
  verifyHttpPath: 'ফাইল পাথ',
  verifyHttpContent: 'ফাইলের কনটেন্ট',
  verifyHint: 'উপরের রেকর্ড বা ফাইল যোগ করার পর যাচাই বাটনে ক্লিক করুন।',
  stackTitle: 'সনাক্ত প্রযুক্তি স্ট্যাক',
  stackEmpty: 'কোনো প্রযুক্তি সনাক্ত হয়নি',
  portsTitle: 'লাইভ পোর্ট স্ক্যান',
  portsEmpty: 'কোনো খোলা পোর্ট পাওয়া যায়নি',
  excludedTitle: 'প্রসঙ্গবিরোধী সিভিই বাদ দেওয়া হয়েছে',
  excludedEmpty: 'কোনো সিভিই বাদ দেওয়া হয়নি',
  scanNow: 'স্ক্যান করুন',
  scanningNow: 'স্ক্যান চলছে',
};

const EN: LabTranslations = {
  disclaimerTitle: 'Authorized security testing',
  disclaimerBody:
    'Use this tool only against systems you own or have written permission to test. Domain ownership verification is mandatory before deep active scans. Unauthorized use is illegal.',
  mapTitle: 'Live Hacking Lab Map',
  mapSubtitle:
    'Real OpenStreetMap tiles show scan targets, resolved IP addresses, and the scanner node in real time.',
  mapLiveBadge: 'LIVE',
  mapHeatOn: 'Disable heatmap',
  mapHeatOff: 'Enable heatmap',
  mapFocusScan: 'Focus scan',
  mapResetView: 'Reset view',
  mapScannerOrigin: 'Scanner node',
  mapOriginUnknown: 'Scanner origin unavailable',
  mapLegendCritical: 'Critical',
  mapLegendHigh: 'High',
  mapLegendClean: 'Clean',
  mapLegendScanner: 'Scanner',
  mapNodesLabel: 'threat nodes',
  mapScanPointsLabel: 'scan points',
  mapNoScan: 'No scan has been run yet',
  mapLoading: 'Loading map...',
  terminalTitle: 'Live Scan Terminal',
  terminalSubtitle: 'Every backend scan phase streams over the realtime socket channel.',
  terminalEmpty: 'Start a scan to see live logs here.',
  terminalClear: 'Clear',
  terminalConnected: 'connected',
  terminalDisconnected: 'disconnected',
  terminalWaiting: 'Waiting for scan...',
  chartsTitle: 'Vulnerability Analytics',
  chartsSubtitle: 'Risk distribution and open-port summary after each scan.',
  chartsSeverity: 'Severity',
  chartsNoData: 'No results yet',
  chartsCritical: 'Critical',
  chartsHigh: 'High',
  chartsMedium: 'Medium',
  chartsLow: 'Low',
  chartsInfo: 'Info',
  chartsOpenPorts: 'Open ports',
  chartsPortsEmpty: 'No open ports discovered',
  progressTitle: 'Scan Progress',
  progressIdle: 'Start a scan',
  progressScanning: 'Scanning',
  progressDone: 'Scan complete',
  verifyTitle: 'Domain Ownership Verification',
  verifySubtitle:
    'Prove you control the domain before active port scanning and vulnerability probes are allowed.',
  verifyDomainPlaceholder: 'example.com',
  verifyCheckBtn: 'Verify',
  verifyChecking: 'Verifying...',
  verifyMethodDns: 'DNS TXT record',
  verifyMethodHttp: 'HTTP file',
  verifyVerified: 'Verified',
  verifyPending: 'Not verified yet',
  verifyTokenLabel: 'Token',
  verifyTxtHost: 'TXT record host',
  verifyTxtValue: 'TXT record value',
  verifyHttpPath: 'File path',
  verifyHttpContent: 'File content',
  verifyHint: 'Add the record or file above, then click Verify.',
  stackTitle: 'Detected technology stack',
  stackEmpty: 'No technology fingerprint detected',
  portsTitle: 'Live port scan',
  portsEmpty: 'No open ports discovered',
  excludedTitle: 'Contextually excluded CVEs',
  excludedEmpty: 'No CVEs were excluded',
  scanNow: 'Scan',
  scanningNow: 'Scanning',
};

export function getLabTranslations(lang: Language): LabTranslations {
  return lang === 'bn' ? BN : EN;
}
