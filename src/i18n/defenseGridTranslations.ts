import type { Language } from '../types/cyber.ts';

export interface DefenseGridTranslations {
  title: string;
  subtitle: string;
  live: string;
  sensorOnline: string;
  sensorOffline: string;
  autoDefense: string;
  autoDefenseOn: string;
  autoDefenseOff: string;
  refresh: string;
  clear: string;
  statEvents: string;
  statBlocked: string;
  statAttackers: string;
  statSensorRequests: string;
  alertTitle: string;
  alertBody: (ip: string, category: string) => string;
  streamTitle: string;
  streamSubtitle: string;
  emptyStream: string;
  filterAll: string;
  filterSensor: string;
  filterFeed: string;
  filterBlocked: string;
  sourceSensor: string;
  sourceFeed: string;
  actionObserved: string;
  actionBlocked: string;
  actionTarpitted: string;
  actionReported: string;
  block: string;
  report: string;
  unblockHint: string;
  sitesTitle: string;
  sitesSubtitle: string;
  sitesEmpty: string;
  addSitePlaceholder: string;
  addSite: string;
  addSiteNote: string;
  recheck: string;
  remove: string;
  statusShielded: string;
  statusAlert: string;
  lastChecked: string;
  noAlert: string;
  incidentsTitle: string;
  incidentsSubtitle: string;
  incidentsEmpty: string;
  topAttackersTitle: string;
  topAttackersEmpty: string;
  abuseReportTitle: string;
  abuseReportEmpty: string;
  copy: string;
  copied: string;
  close: string;
  safeIpPlaceholder: string;
  addSafeIp: string;
  safeIpNote: string;
  categoryLabels: Record<string, string>;
}

const CATEGORY_BN: Record<string, string> = {
  sqli: 'SQL ইনজেকশন',
  xss: 'XSS',
  'path-traversal': 'পাথ ট্রাভার্সাল',
  rce: 'RCE / কমান্ড ইনজেকশন',
  'credential-stuffing': 'ক্রেডেনশিয়াল স্টাফিং',
  scanner: 'স্ক্যানার',
  ddos: 'DDoS / ফ্লাড',
  bruteforce: 'ব্রুটফোর্স',
  honeypot: 'হানিপট প্রোব',
  'botnet-c2': 'বটনেট C2',
  phishing: 'ফিশিং',
  other: 'অন্যান্য',
};

const CATEGORY_EN: Record<string, string> = {
  sqli: 'SQL injection',
  xss: 'XSS',
  'path-traversal': 'Path traversal',
  rce: 'RCE / command injection',
  'credential-stuffing': 'Credential stuffing',
  scanner: 'Scanner',
  ddos: 'DDoS / flood',
  bruteforce: 'Bruteforce',
  honeypot: 'Honeypot probe',
  'botnet-c2': 'Botnet C2',
  phishing: 'Phishing',
  other: 'Other',
};

const BN: DefenseGridTranslations = {
  title: 'গ্লোবাল ডিফেন্স গ্রিড',
  subtitle:
    'আসল হানিপট, রিকোয়েস্ট সিগনেচার ও গ্লোবাল থ্রেট ফিড থেকে লাইভ আক্রমণ শনাক্ত করে অটোমেটিক ব্লক, টারপিট ও অ্যাবিউজ রিপোর্ট তৈরি করে।',
  live: 'লাইভ',
  sensorOnline: 'সেন্সর সক্রিয়',
  sensorOffline: 'সেন্সর অফলাইন',
  autoDefense: 'অটো ডিফেন্স',
  autoDefenseOn: 'অটো ডিফেন্স চালু',
  autoDefenseOff: 'অটো ডিফেন্স বন্ধ',
  refresh: 'রিফ্রেশ',
  clear: 'স্ট্রিম ক্লিয়ার',
  statEvents: 'শনাক্ত ইভেন্ট',
  statBlocked: 'অটো-ব্লকড',
  statAttackers: 'ইউনিক আক্রমণকারী',
  statSensorRequests: 'সেন্সর রিকোয়েস্ট',
  alertTitle: 'লাইভ আক্রমণ শনাক্ত',
  alertBody: (ip, category) =>
    `${ip} থেকে ${category} শনাক্ত হয়েছে। সোর্সকে অটোমেটিক ডিফেন্স কিউতে পাঠানো হয়েছে।`,
  streamTitle: 'লাইভ অ্যাটাক স্ট্রিম',
  streamSubtitle: 'আসল রিকোয়েস্ট সেন্সর + গ্লোবাল থ্রেট ফিড — কোনো ডেটা বানানো নয়।',
  emptyStream: 'এখনো কোনো আক্রমণ শনাক্ত হয়নি। সেন্সর চালু আছে।',
  filterAll: 'সব',
  filterSensor: 'সেন্সর',
  filterFeed: 'ফিড',
  filterBlocked: 'ব্লকড',
  sourceSensor: 'সেন্সর',
  sourceFeed: 'ফিড',
  actionObserved: 'পর্যবেক্ষণ',
  actionBlocked: 'ব্লকড',
  actionTarpitted: 'টারপিট',
  actionReported: 'রিপোর্টেড',
  block: 'ব্লক',
  report: 'অ্যাবিউজ রিপোর্ট',
  unblockHint: 'ব্লক করা আইপি ডিফেন্স প্যানেল থেকে আনব্লক করা যায়।',
  sitesTitle: 'সুরক্ষিত সাইট',
  sitesSubtitle: 'শুধু নিজের বা লিখিত অনুমোদিত ডোমেইন যোগ করুন। সিস্টেম রিয়েল DNS, TLS ও হেডার মনিটর করে।',
  sitesEmpty: 'এখনো কোনো সাইট শিল্ডে যোগ করা হয়নি।',
  addSitePlaceholder: 'example.com',
  addSite: 'শিল্ড চালু',
  addSiteNote: 'শিল্ড চালু করলে ডোমেইনের বর্তমান অবস্থা বেসলাইন হিসেবে সংরক্ষিত হবে।',
  recheck: 'রিচেক',
  remove: 'সরান',
  statusShielded: 'সুরক্ষিত',
  statusAlert: 'অ্যালার্ট',
  lastChecked: 'সর্বশেষ চেক',
  noAlert: 'কোনো পরিবর্তন নেই',
  incidentsTitle: 'বিশ্বজুড়ে আক্রমণের রিয়েল রিপোর্ট',
  incidentsSubtitle: 'পাবলিক থ্রেট নিউজ ও ইনসিডেন্ট ফিড থেকে আসল রিপোর্ট।',
  incidentsEmpty: 'এই মুহূর্তে কোনো ইনসিডেন্ট রিপোর্ট নেই।',
  topAttackersTitle: 'শীর্ষ আক্রমণকারী',
  topAttackersEmpty: 'কোনো আক্রমণকারী নেই।',
  abuseReportTitle: 'অ্যাবিউজ রিপোর্ট',
  abuseReportEmpty: 'কোনো আইপির পাশে “অ্যাবিউজ রিপোর্ট” চাপলে RDAP থেকে আসল abuse contact সহ রিপোর্ট তৈরি হবে।',
  copy: 'কপি',
  copied: 'কপি হয়েছে',
  close: 'বন্ধ',
  safeIpPlaceholder: 'নিজের আইপি (যেমন: 203.0.113.10)',
  addSafeIp: 'সেফ লিস্টে রাখুন',
  safeIpNote: 'নিজের আইপি সেফ লিস্টে রাখলে ভুল করে অটো-ব্লক হবে না।',
  categoryLabels: CATEGORY_BN,
};

const EN: DefenseGridTranslations = {
  title: 'Global Defense Grid',
  subtitle:
    'Detects live attacks from real honeypots, request signatures and global threat feeds, then auto-blocks, tarpits and prepares abuse reports.',
  live: 'Live',
  sensorOnline: 'Sensor online',
  sensorOffline: 'Sensor offline',
  autoDefense: 'Auto defense',
  autoDefenseOn: 'Auto defense on',
  autoDefenseOff: 'Auto defense off',
  refresh: 'Refresh',
  clear: 'Clear stream',
  statEvents: 'Detected events',
  statBlocked: 'Auto-blocked',
  statAttackers: 'Unique attackers',
  statSensorRequests: 'Sensor requests',
  alertTitle: 'Live attack detected',
  alertBody: (ip, category) =>
    `${category} detected from ${ip}. The source has been pushed to the automatic defense queue.`,
  streamTitle: 'Live attack stream',
  streamSubtitle: 'Real request sensors + global threat feeds — no fabricated data.',
  emptyStream: 'No attack detected yet. The sensor is armed.',
  filterAll: 'All',
  filterSensor: 'Sensor',
  filterFeed: 'Feed',
  filterBlocked: 'Blocked',
  sourceSensor: 'Sensor',
  sourceFeed: 'Feed',
  actionObserved: 'Observed',
  actionBlocked: 'Blocked',
  actionTarpitted: 'Tarpitted',
  actionReported: 'Reported',
  block: 'Block',
  report: 'Abuse report',
  unblockHint: 'Blocked IPs can be released from the defense panel.',
  sitesTitle: 'Protected sites',
  sitesSubtitle: 'Add only domains you own or are authorized to test. The system monitors real DNS, TLS and headers.',
  sitesEmpty: 'No site has been added to a shield yet.',
  addSitePlaceholder: 'example.com',
  addSite: 'Activate shield',
  addSiteNote: 'Activating a shield stores the current posture as a baseline.',
  recheck: 'Recheck',
  remove: 'Remove',
  statusShielded: 'Shielded',
  statusAlert: 'Alert',
  lastChecked: 'Last checked',
  noAlert: 'No change',
  incidentsTitle: 'Real-world attack reports',
  incidentsSubtitle: 'Actual reports from public threat news and incident feeds.',
  incidentsEmpty: 'No incident report right now.',
  topAttackersTitle: 'Top attackers',
  topAttackersEmpty: 'No attackers yet.',
  abuseReportTitle: 'Abuse report',
  abuseReportEmpty: 'Press “Abuse report” next to an IP to generate a real report with RDAP abuse contacts.',
  copy: 'Copy',
  copied: 'Copied',
  close: 'Close',
  safeIpPlaceholder: 'Your IP (e.g. 203.0.113.10)',
  addSafeIp: 'Add to safe list',
  safeIpNote: 'Keep your own IP in the safe list to prevent accidental auto-blocking.',
  categoryLabels: CATEGORY_EN,
};

export function getDefenseGridTranslations(lang: Language): DefenseGridTranslations {
  return lang === 'bn' ? BN : EN;
}
