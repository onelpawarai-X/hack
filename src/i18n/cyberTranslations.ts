import type { Language, ThreatSeverity } from '../types/cyber';

export interface CyberTranslations {
  appName: string;
  liveSweepActive: string;
  sweepPaused: string;
  nextSweepLabel: string;
  scanNowBtn: string;
  scanningNow: string;
  lastScanLabel: string;
  radarTitle: string;
  radarSubtitle: string;
  modeGlobe3d: string;
  modeTactical2d: string;
  zoomInBtn: string;
  zoomOutBtn: string;
  resetViewBtn: string;
  pauseSweepBtn: string;
  resumeSweepBtn: string;
  legendCritical: string;
  legendHigh: string;
  legendPinned: string;
  legendDefended: string;
  legendSelected: string;
  geoNodesLabel: string;
  inspectorTitle: string;
  inspectorEmpty: string;
  ipLabel: string;
  locationLabel: string;
  addressLabel: string;
  coordsLabel: string;
  timezoneLabel: string;
  asnLabel: string;
  ispLabel: string;
  reverseDnsLabel: string;
  flagsLabel: string;
  openPortsLabel: string;
  knownVulnsLabel: string;
  cidrLabel: string;
  abuseContactLabel: string;
  proxyDetected: string;
  torExitDetected: string;
  hostingNode: string;
  directOrigin: string;
  feedSourceLabel: string;
  defendBlockIpBtn: string;
  defendedBlockedBadge: string;
  deepScanIpBtn: string;
  metrics: {
    activeAttackers: string;
    c2Botnets: string;
    phishingTraps: string;
    activeDefenseShields: string;
  };
  scanner: {
    title: string;
    subtitle: string;
    placeholder: string;
    scanBtn: string;
    scanningBtn: string;
    quickProbesLabel: string;
    probePhish: string;
    probeAttackerIp: string;
    probeCleanGoogle: string;
    probeCleanIp: string;
    probeCve: string;
    verdictLabel: string;
    feedHitsTitle: string;
    attributionTitle: string;
    bgpTitle: string;
    focusOnMapBtn: string;
    activateShieldBtn: string;
    defendIpActionBtn: string;
    shieldActivatedMsg: string;
    dnsTitle: string;
    rdapTitle: string;
    emailSecurityLabel: string;
    emailProtected: string;
    emailWeak: string;
    emailMissing: string;
    tlsTitle: string;
    httpTitle: string;
    securityTxtLabel: string;
    robotsTxtLabel: string;
    waybackTitle: string;
    subdomainsTitle: string;
    cveDetailsTitle: string;
    cookieIssuesLabel: string;
    hardeningTitle: string;
    hardeningClean: string;
    webSignalsTitle: string;
    tlsValid: string;
    tlsInvalid: string;
    daysLeft: string;
    missingHeaders: string;
    allHeadersPresent: string;
    noFeedHits: string;
  };
  forensics: {
    title: string;
    subtitle: string;
    dropzoneTitle: string;
    dropzoneHint: string;
    selectFileBtn: string;
    analyzingBtn: string;
    formatLabel: string;
    mimeMismatchWarn: string;
    anomalyWarnTitle: string;
    fileSizeLabel: string;
    entropyLabel: string;
    trailingBytesLabel: string;
    trailingPreviewLabel: string;
    pipelineTitle: string;
    thumbnailTitle: string;
    hashesTitle: string;
    cameraTitle: string;
    noExifFound: string;
    gpsTitle: string;
    noGpsFound: string;
    pinGpsOnMapBtn: string;
    openOsmBtn: string;
    embeddedTitle: string;
    noEmbeddedStrings: string;
    embeddedIpsTitle: string;
    originNoteTitle: string;
    rawTagsTitle: string;
    filterTagsPlaceholder: string;
  };
  tabs: {
    attackers: string;
    phishing: string;
    globalThreats: string;
    defenseCenter: string;
  };
  tables: {
    ipAddress: string;
    threatType: string;
    originLocation: string;
    asnIsp: string;
    sourceFeed: string;
    actions: string;
    traceOnRadar: string;
    defendNow: string;
    defendedBadge: string;
    deepScan: string;
    filterPlaceholder: string;
    phishWarningNote: string;
    takedownDomainBtn: string;
    sinkholedBadge: string;
    inspectSafely: string;
    ransomwareLinked: string;
    standardCve: string;
    addedDate: string;
    countermeasureBtn: string;
    inspectTarget: string;
    openReport: string;
    feedHealthTitle: string;
  };
  defense: {
    subtitle: string;
    protectedWebsitesTitle: string;
    noShieldsYet: string;
    blockedAttackersTitle: string;
    noBlockedIpsYet: string;
    sinkholedDomainsTitle: string;
    noSinkholesYet: string;
    firewallBundleTitle: string;
    copyBtn: string;
    copiedBtn: string;
    recheckBtn: string;
    removeBtn: string;
    reportAbuseEmailBtn: string;
    reportSafeBrowsingBtn: string;
    reportNetcraftBtn: string;
    statusShielded: string;
    statusAlert: string;
  };
  severityLabels: Record<ThreatSeverity, string>;
}

const bn: CyberTranslations = {
  appName: 'SentinelGlobe',
  liveSweepActive: 'লাইভ গ্লোবাল স্ক্যান চালু',
  sweepPaused: 'অটো-স্ক্যান বিরত',
  nextSweepLabel: 'পরবর্তী সুইপ',
  scanNowBtn: 'এখনই স্ক্যান করুন',
  scanningNow: 'স্ক্যান হচ্ছে...',
  lastScanLabel: 'সর্বশেষ আপডেট',
  radarTitle: 'রিয়েল ৩ডি গ্লোব ও ট্যাকটিক্যাল সাইবার থ্রেট রাডার',
  radarSubtitle:
    'সক্রিয় আক্রমণকারী IP, গ্রেট-সার্কেল অ্যাটাক আর্ক, স্ক্যানকৃত IP ও ছবির GPS রিয়েল-টাইম ৩ডি পৃথিবী ও ২ডি রাডারে দেখুন — ড্র্যাগ করে ঘোরান, জুম করুন বা বিন্দুতে ক্লিক করুন।',
  modeGlobe3d: '৩ডি গ্লোব রাডার',
  modeTactical2d: '২ডি ট্যাকটিক্যাল ম্যাপ',
  zoomInBtn: 'জুম +',
  zoomOutBtn: 'জুম -',
  resetViewBtn: 'রিসেট',
  pauseSweepBtn: 'সুইপ থামান',
  resumeSweepBtn: 'সুইপ চালু করুন',
  legendCritical: 'অতি ঝুঁকিপূর্ণ / C2 বা মাল্টি-ফিড',
  legendHigh: 'সক্রিয় আক্রমণকারী IP',
  legendPinned: 'স্ক্যানকৃত IP / ছবির GPS',
  legendDefended: 'প্রতিরোধ ও ব্লকড (Shield)',
  legendSelected: 'টার্গেট লক',
  geoNodesLabel: 'ম্যাপকৃত নোড',
  inspectorTitle: 'আক্রমণকারীর অবস্থান, ঠিকানা ও ডিফেন্স',
  inspectorEmpty: 'রাডারে যেকোনো বিন্দুতে ক্লিক করুন অথবা নিচে IP/ছবি স্ক্যান করে ঠিকানা দেখুন।',
  ipLabel: 'উৎস IP / টার্গেট',
  locationLabel: 'শহর ও দেশ',
  addressLabel: 'বাস্তব ভৌত ঠিকানা',
  coordsLabel: 'স্থানাঙ্ক (Lat / Lon)',
  timezoneLabel: 'টাইমজোন',
  asnLabel: 'নেটওয়ার্ক ASN',
  ispLabel: 'ISP / হোস্টিং সংস্থা',
  reverseDnsLabel: 'রিভার্স DNS (PTR)',
  flagsLabel: 'নেটওয়ার্ক ধরন',
  openPortsLabel: 'উন্মুক্ত পোর্ট (Shodan)',
  knownVulnsLabel: 'পরিচিত দুর্বলতা (CVEs)',
  cidrLabel: 'RDAP নেটওয়ার্ক ব্লক',
  abuseContactLabel: 'Abuse ইমেইল (RDAP)',
  proxyDetected: 'প্রক্সি / VPN চিহ্নিত',
  torExitDetected: 'টর (Tor) এক্সিট নোড চিহ্নিত',
  hostingNode: 'ডেটাসেন্টার / হোস্টিং সার্ভার',
  directOrigin: 'সরাসরি ISP অ্যাসাইনমেন্ট',
  feedSourceLabel: 'সনাক্তকারী সোর্স',
  defendBlockIpBtn: 'প্রতিরোধ ও ফায়ারওয়াল ব্লক চালু করুন',
  defendedBlockedBadge: 'প্রতিরোধ সক্রিয় (ব্লকড ও মনিটরড)',
  deepScanIpBtn: 'এই IP-তে গভীর স্ক্যান চালু করুন',
  metrics: {
    activeAttackers: 'সক্রিয় আক্রমণকারী IP',
    c2Botnets: 'বটনেট C2 সার্ভার',
    phishingTraps: 'ফিশিং ও ফাঁদ URL',
    activeDefenseShields: 'সক্রিয় ডিফেন্ড ও শিল্ড',
  },
  scanner: {
    title: 'লাইভ ওয়েবসাইট, ডোমেইন, IP ও সিস্টেম ডিফেন্ড স্ক্যানার',
    subtitle:
      'যেকোনো IP, ওয়েবসাইট বা ডোমেইন লিখুন — ম্যাপে অবস্থান ও ঠিকানা দেখাবে, DNS/SPF/DMARC, TLS সাইফার ও Shodan CVE অডিট করবে এবং এক ক্লিকে সিস্টেম সুরক্ষার লাইভ ডিফেন্ড শিল্ড চালু করবে।',
    placeholder: 'IPv4 (যেমন: 1.1.1.1), ডোমেইন/URL, অথবা CVE-2024-3094 লিখুন...',
    scanBtn: 'গভীর OSINT স্ক্যান',
    scanningBtn: 'গভীর বিশ্লেষণ চলছে...',
    quickProbesLabel: 'লাইভ টেস্ট প্রোব',
    probePhish: 'লাইভ ফিশিং ফাঁদ (লাল)',
    probeAttackerIp: 'লাইভ আক্রমণকারী IP (লাল)',
    probeCleanGoogle: 'google.com ডিপ স্ক্যান',
    probeCleanIp: 'IP ম্যাপ ও BGP (1.1.1.1)',
    probeCve: 'CVE-2024-3094 তদন্ত',
    verdictLabel: 'নিরাপত্তা সিদ্ধান্ত',
    feedHitsTitle: 'থ্রেট ইন্টেলিজেন্স ফিডে ম্যাচ',
    attributionTitle: 'উৎস অবস্থান, বাস্তব ঠিকানা ও পোর্ট অডিট',
    bgpTitle: 'BGP রাউটিং ও প্রিফিক্স (RIPEstat)',
    focusOnMapBtn: 'ম্যাপে দেখুন',
    activateShieldBtn: 'ওয়েবসাইটে ডিফেন্ড শিল্ড চালু করুন',
    defendIpActionBtn: 'আক্রমণকারী IP ব্লক ও মনিটর করুন',
    shieldActivatedMsg: 'লাইভ ডিফেন্ড শিল্ড ও কনটিনিউয়াস ওয়াচডগ চালু হয়েছে!',
    dnsTitle: 'লাইভ DNS, SPF, DMARC ও CAA',
    rdapTitle: 'ডোমেইন রেজিস্ট্রার ও RDAP তথ্য',
    emailSecurityLabel: 'ইমেইল অ্যান্টি-স্পুফিং (SPF/DMARC)',
    emailProtected: 'সুরক্ষিত (SPF + DMARC Enforce)',
    emailWeak: 'দুর্বল বা মনিটর-মাত্র পলিসি',
    emailMissing: 'SPF ও DMARC অনুপস্থিত',
    tlsTitle: 'TLS / SSL সার্টিফিকেট ও সাইফার অডিট',
    httpTitle: 'HTTP নিরাপত্তা হেডার ও কুকি অডিট',
    securityTxtLabel: 'security.txt',
    robotsTxtLabel: 'robots.txt',
    waybackTitle: 'ওয়েব আর্কাইভ ইতিহাস (Wayback)',
    subdomainsTitle: 'আবিষ্কৃত সাবডোমেইন (Certificate Transparency)',
    cveDetailsTitle: 'অফিসিয়াল MITRE CVE-5.2 ঝুঁকি ও CVSS অডিট',
    cookieIssuesLabel: 'কুকি নিরাপত্তা সমস্যা',
    hardeningTitle: 'সিস্টেম সুরক্ষিত করার পদক্ষেপ (Defense Hardening Plan)',
    hardeningClean: 'কোনো জরুরি প্রতিরক্ষামূলক ঘাটতি পাওয়া যায়নি।',
    webSignalsTitle: 'গ্লোবাল ওয়েব ব্রিচ ও সাইবার হামলা ইনডেক্স',
    tlsValid: 'ভেরিফায়েড ও বৈধ TLS',
    tlsInvalid: 'অবৈধ বা অনুপস্থিত TLS',
    daysLeft: 'দিন বাকি',
    missingHeaders: 'অনুপস্থিত নিরাপত্তা হেডার',
    allHeadersPresent: 'প্রয়োজনীয় সব নিরাপত্তা হেডার উপস্থিত রয়েছে',
    noFeedHits: 'Blocklist.de, CINS Army, Feodo C2, Tor Exit বা OpenPhish-এ কোনো বিপজ্জনক ম্যাচ পাওয়া যায়নি।',
  },
  forensics: {
    title: 'গভীরতম পিকচার ফরেনসিকস, ডিভাইস ও IP এক্সট্রাক্টর',
    subtitle:
      'যেকোনো ছবি আপলোড করুন — ফোন/ক্যামেরার মডেল ও সিরিয়াল, EXIF/XMP/PNG-Zlib মেটাডাটা, মূল এমবেডেড থাম্বনেইল, GPS ও বাস্তব রাস্তার ঠিকানা, লুকানো ফাইল-পাথ/বাইনারি পে-লোড এবং ছবির ভেতরের যেকোনো পাবলিক IP স্বয়ংক্রিয়ভাবে ট্রেস করে ম্যাপে দেখানো হবে।',
    dropzoneTitle: 'গভীরতম বিশ্লেষণের জন্য যেকোনো পিকচার এখানে দিন বা নির্বাচন করুন',
    dropzoneHint: 'সমর্থিত ফরম্যাট: JPEG, PNG (zTXt/iTXt ডিকম্প্রেস সহ), WebP, TIFF, HEIC, GIF (সর্বোচ্চ ১৫ MB)',
    selectFileBtn: 'ছবি নির্বাচন করুন',
    analyzingBtn: 'গভীর ফরেনসিক এক্সট্রাকশন চলছে...',
    formatLabel: 'শনাক্তকৃত বাইনারি ফরম্যাট',
    mimeMismatchWarn: 'সতর্কতা: ফাইলের এক্সটেনশন/MIME ও ভেতরের বাইনারি ফরম্যাট ভিন্ন!',
    anomalyWarnTitle: 'ফরেনসিক নিরাপত্তা ও বাইনারি সতর্কতা',
    fileSizeLabel: 'ফাইল সাইজ',
    entropyLabel: 'শ্যানন এন্ট্রপি',
    trailingBytesLabel: 'EOF-এর পর বাড়তি বাইট (Stego চেক)',
    trailingPreviewLabel: 'EOF-পরবর্তী লুকানো ডেটা প্রিভিউ',
    pipelineTitle: 'কন্টেইনার ও রি-কম্প্রেশন বিশ্লেষণ (JPEG/PNG Pipeline)',
    thumbnailTitle: 'এমবেডেড ক্যামেরা থাম্বনেইল (Tamper চেক)',
    hashesTitle: 'ক্রিপ্টোগ্রাফিক হ্যাশ (SHA-256 / SHA-1 / MD5)',
    cameraTitle: 'ফোন / ক্যামেরা, সিরিয়াল, সফটওয়্যার ও সময়কাল',
    noExifFound: 'এই ছবিতে ক্যামেরা EXIF ট্যাগ পাওয়া যায়নি (সম্ভবত WhatsApp/Facebook/ওয়েব এক্সপোর্ট থেকে মেটাডাটা স্ট্রিপ করা হয়েছে)।',
    gpsTitle: 'ছবির GPS স্থানাঙ্ক, কম্পাস ও বাস্তব ঠিকানা',
    noGpsFound: 'এই ছবির ভেতরে GPS লোকেশন মেটাডাটা নেই।',
    pinGpsOnMapBtn: 'ছবির লোকেশন ম্যাপে দেখুন',
    openOsmBtn: 'OpenStreetMap-এ খুলুন',
    embeddedTitle: 'বাইনারির ভেতর থেকে প্রাপ্ত IP, URL, ফাইল-পাথ ও ইমেইল',
    noEmbeddedStrings: 'ভেতরে কোনো লুকানো URL, পাবলিক IP, ফাইল-পাথ বা কোড পাওয়া যায়নি।',
    embeddedIpsTitle: 'ছবির ভেতরে পাওয়া IP ঠিকানার অটো-ট্রেস ও ম্যাপ অবস্থান',
    originNoteTitle: 'ফরেনসিক উৎস ও গোপনীয়তা সারসংক্ষেপ',
    rawTagsTitle: 'সম্পূর্ণ এক্সট্রাক্টেড EXIF / XMP / IPTC / ICC ট্যাগসমূহ',
    filterTagsPlaceholder: 'ট্যাগ নাম বা মান দিয়ে খুঁজুন...',
  },
  tabs: {
    attackers: 'সক্রিয় আক্রমণকারী',
    phishing: 'ফিশিং ও ফাঁদ URL',
    globalThreats: 'বিশ্বব্যাপী থ্রেট',
    defenseCenter: 'ডিফেন্ড ও সিস্টেম শিল্ড',
  },
  tables: {
    ipAddress: 'IP / পোর্ট',
    threatType: 'হামলার ধরন',
    originLocation: 'দেশ ও শহর',
    asnIsp: 'ASN ও ISP',
    sourceFeed: 'থ্রেট ফিড',
    actions: 'প্রতিরোধ অ্যাকশন',
    traceOnRadar: 'ম্যাপে দেখুন',
    defendNow: 'ডিফেন্ড করুন',
    defendedBadge: 'শিল্ডেড / ব্লকড',
    deepScan: 'ডিপ স্ক্যান',
    filterPlaceholder: 'IP, দেশ, হ্যাকার বা CVE দিয়ে খুঁজুন...',
    phishWarningNote:
      'সতর্কতা: নিচের সব URL ইন্টারনেট থেকে পাওয়া লাইভ ফিশিং ফাঁদ। সরাসরি ভিজিট না করে "ব্লক ও টেকডাউন" বা "নিরাপদ স্ক্যান" ব্যবহার করুন।',
    takedownDomainBtn: 'বন্ধ / টেকডাউন করুন',
    sinkholedBadge: 'সিঙ্কহোল ব্লকড',
    inspectSafely: 'নিরাপদ স্ক্যান',
    ransomwareLinked: 'র‍্যানসমওয়্যার যুক্ত',
    standardCve: 'সক্রিয় এক্সপ্লয়েট',
    addedDate: 'যুক্ত তারিখ',
    countermeasureBtn: 'তদন্ত ও প্রতিরোধ',
    inspectTarget: 'লক্ষ্য স্ক্যান',
    openReport: 'রিপোর্ট দেখুন',
    feedHealthTitle: 'সক্রিয় থ্রেট ফিড অবস্থা',
  },
  defense: {
    subtitle:
      'বাস্তব Nginx/iptables/Cloudflare ফায়ারওয়াল রুল, DNS সিঙ্কহোল, RDAP Abuse ইমেইল টেকডাউন এবং আপনার ওয়েবসাইটের ২৪/৭ ওয়াচডগ শিল্ড এখান থেকে নিয়ন্ত্রণ করুন।',
    protectedWebsitesTitle: 'সুরক্ষিত ওয়েবসাইট ও সিস্টেম ওয়াচডগ শিল্ড',
    noShieldsYet: 'এখনো কোনো ওয়েবসাইটে ডিফেন্ড শিল্ড চালু করা হয়নি — উপরের স্ক্যানারে যেকোনো সাইট স্ক্যান করে শিল্ড চালু করুন।',
    blockedAttackersTitle: 'প্রতিরোধকৃত আক্রমণকারী IP ও RDAP Abuse টেকডাউন',
    noBlockedIpsYet: 'এখনো কোনো আক্রমণকারী IP ব্লক করা হয়নি — সক্রিয় আক্রমণকারী ট্যাব থেকে "ডিফেন্ড করুন" চাপুন।',
    sinkholedDomainsTitle: 'ফিশিং ও ফাঁদ URL সিঙ্কহোল ও টেকডাউন লিস্ট',
    noSinkholesYet: 'এখনো কোনো ফিশিং সাইট সিঙ্কহোল করা হয়নি — ফিশিং ট্যাব থেকে "বন্ধ / টেকডাউন করুন" চাপুন।',
    firewallBundleTitle: 'প্রোডাকশন ফায়ারওয়াল ও DNS সিঙ্কহোল বান্ডেল (কপি করে সার্ভারে বসান)',
    copyBtn: 'কপি করুন',
    copiedBtn: 'কপি হয়েছে',
    recheckBtn: 'পুনরায় অডিট',
    removeBtn: 'সরান',
    reportAbuseEmailBtn: 'ISP Abuse টেকডাউন ইমেইল',
    reportSafeBrowsingBtn: 'Google Safe Browsing রিপোর্ট',
    reportNetcraftBtn: 'Netcraft টেকডাউন রিপোর্ট',
    statusShielded: 'সুরক্ষিত (Watchdog Active)',
    statusAlert: 'সতর্কতা / হার্ডেনিং প্রয়োজন',
  },
  severityLabels: {
    CRITICAL: 'অতি বিপজ্জনক (CRITICAL)',
    HIGH: 'উচ্চ ঝুঁকি (HIGH)',
    ELEVATED: 'সতর্কতা (ELEVATED)',
    CLEAN: 'নিরাপদ / পরিষ্কার (CLEAN)',
  },
};

const en: CyberTranslations = {
  appName: 'SentinelGlobe',
  liveSweepActive: 'Live Global Sweep Active',
  sweepPaused: 'Auto-Sweep Paused',
  nextSweepLabel: 'Next Sweep',
  scanNowBtn: 'Scan Now',
  scanningNow: 'Scanning...',
  lastScanLabel: 'Last Sweep',
  radarTitle: 'Real 3D Globe & Tactical Cyber Threat Radar',
  radarSubtitle:
    'Live geolocated attacker IPs, great-circle attack arcs, scanned targets, and photo GPS pins rendered on interactive 3D Earth & 2D Tactical Radar — drag to rotate, scroll to zoom, or click any node.',
  modeGlobe3d: '3D Globe Radar',
  modeTactical2d: '2D Tactical Map',
  zoomInBtn: 'Zoom +',
  zoomOutBtn: 'Zoom -',
  resetViewBtn: 'Reset',
  pauseSweepBtn: 'Pause Sweep',
  resumeSweepBtn: 'Resume Sweep',
  legendCritical: 'Critical / C2 or Multi-Feed',
  legendHigh: 'Active Attacker IP',
  legendPinned: 'Scanned IP / Photo GPS',
  legendDefended: 'Blocked & Shielded',
  legendSelected: 'Target Lock',
  geoNodesLabel: 'Mapped Nodes',
  inspectorTitle: 'Attacker Location, Address & Defense',
  inspectorEmpty: 'Click any node on the radar or scan an IP/image below to trace its origin and block it.',
  ipLabel: 'Origin IP / Target',
  locationLabel: 'City & Country',
  addressLabel: 'Resolved Physical Address',
  coordsLabel: 'Coordinates (Lat / Lon)',
  timezoneLabel: 'Timezone',
  asnLabel: 'Autonomous System (ASN)',
  ispLabel: 'ISP / Hosting Provider',
  reverseDnsLabel: 'Reverse DNS (PTR)',
  flagsLabel: 'Infrastructure Class',
  openPortsLabel: 'Exposed Ports (Shodan)',
  knownVulnsLabel: 'Known Host CVEs',
  cidrLabel: 'RDAP Network CIDR',
  abuseContactLabel: 'Abuse Contact (RDAP)',
  proxyDetected: 'Proxy / VPN Detected',
  torExitDetected: 'Tor Network Exit Node',
  hostingNode: 'Datacenter / Hosting Node',
  directOrigin: 'Direct ISP Allocation',
  feedSourceLabel: 'Detecting Source',
  defendBlockIpBtn: 'Activate Defense Block & Watchdog',
  defendedBlockedBadge: 'DEFENSE ACTIVE (Blocked & Monitored)',
  deepScanIpBtn: 'Launch Deep Scan on This IP',
  metrics: {
    activeAttackers: 'Active Attacker IPs',
    c2Botnets: 'Botnet C2 Servers',
    phishingTraps: 'Live Phishing Traps',
    activeDefenseShields: 'Active Defense Shields',
  },
  scanner: {
    title: 'Live Website, Domain, IP & System Defense Scanner',
    subtitle:
      'Enter any IP, website URL, or domain — maps real location & address, audits DNS/SPF/DMARC, TLS cipher & Shodan CVEs, and lets you deploy a continuous Defense Shield.',
    placeholder: 'Enter IPv4 (e.g. 1.1.1.1), domain/URL, or CVE-2024-3094...',
    scanBtn: 'Deep OSINT Scan',
    scanningBtn: 'Deep Scanning...',
    quickProbesLabel: 'Live Test Probes',
    probePhish: 'Test Live Phishing Trap (Red)',
    probeAttackerIp: 'Test Live Attacker IP (Red)',
    probeCleanGoogle: 'Verify google.com',
    probeCleanIp: 'Trace IP & BGP (1.1.1.1)',
    probeCve: 'Inspect CVE-2024-3094',
    verdictLabel: 'Security Verdict',
    feedHitsTitle: 'Live Threat Feed Matches',
    attributionTitle: 'Origin Address, Map Location & Port Exposure',
    bgpTitle: 'BGP Routing & Prefix (RIPEstat)',
    focusOnMapBtn: 'Pin on Map',
    activateShieldBtn: 'Activate Website Defense Shield',
    defendIpActionBtn: 'Block & Monitor Attacker IP',
    shieldActivatedMsg: 'Live Defense Shield & continuous watchdog activated!',
    dnsTitle: 'Live DNS, SPF, DMARC & CAA',
    rdapTitle: 'Domain Registrar & RDAP Lifecycle',
    emailSecurityLabel: 'Email Anti-Spoofing (SPF/DMARC)',
    emailProtected: 'Protected (SPF + Enforced DMARC)',
    emailWeak: 'Weak or Monitor-Only Policy',
    emailMissing: 'SPF & DMARC Missing',
    tlsTitle: 'TLS / X.509 Certificate & Cipher Audit',
    httpTitle: 'HTTP Security Headers & Cookie Audit',
    securityTxtLabel: 'security.txt',
    robotsTxtLabel: 'robots.txt',
    waybackTitle: 'Web Archive History (Wayback)',
    subdomainsTitle: 'Discovered Subdomains (Certificate Transparency)',
    cveDetailsTitle: 'Official MITRE CVE-5.2 Vulnerability & CVSS Audit',
    cookieIssuesLabel: 'Cookie Security Findings',
    hardeningTitle: 'System Defense Hardening Action Plan',
    hardeningClean: 'No urgent defensive configuration gaps detected.',
    webSignalsTitle: 'Global Web Breach & Attack Signals',
    tlsValid: 'Verified Valid TLS',
    tlsInvalid: 'Invalid or Missing TLS',
    daysLeft: 'days remaining',
    missingHeaders: 'Missing Security Headers',
    allHeadersPresent: 'All core HTTP security headers present',
    noFeedHits: 'No hits across Blocklist.de, CINS Army, Feodo C2, Tor Exit, or OpenPhish live feeds.',
  },
  forensics: {
    title: 'Ultra-Deep Picture Forensics, Device & IP Extractor',
    subtitle:
      'Upload any picture — extracts phone/camera model & serial, EXIF/XMP/PNG-Zlib tags, original embedded EXIF thumbnail, GPS + street address, hidden file paths/trailing payloads, and automatically geolocates any public IP embedded inside.',
    dropzoneTitle: 'Drop or select any picture for ultra-deep forensic extraction',
    dropzoneHint: 'Supports JPEG, PNG (zlib zTXt/iTXt decompression), WebP, TIFF, HEIC, GIF (max 15 MB)',
    selectFileBtn: 'Select Picture',
    analyzingBtn: 'Running Deep Forensics...',
    formatLabel: 'Detected Binary Format',
    mimeMismatchWarn: 'Warning: Declared file MIME/extension does not match binary magic bytes!',
    anomalyWarnTitle: 'Forensic Binary & Payload Warnings',
    fileSizeLabel: 'File Size',
    entropyLabel: 'Shannon Entropy',
    trailingBytesLabel: 'Trailing Bytes After EOF (Stego Check)',
    trailingPreviewLabel: 'Appended Trailing Payload Preview',
    pipelineTitle: 'Container & Re-Compression Pipeline (JPEG/PNG)',
    thumbnailTitle: 'Embedded Camera Thumbnail (Tamper Check)',
    hashesTitle: 'Cryptographic Hashes (SHA-256 / SHA-1 / MD5)',
    cameraTitle: 'Phone / Camera, Serial, Software & Timestamps',
    noExifFound: 'No camera EXIF tags remain in this image (likely stripped by messaging app or web export).',
    gpsTitle: 'Photo GPS Coordinates, Compass & Street Address',
    noGpsFound: 'No embedded GPS location metadata present in this image.',
    pinGpsOnMapBtn: 'Plot Photo Location on Map',
    openOsmBtn: 'Open in OpenStreetMap',
    embeddedTitle: 'Extracted Binary IPs, URLs, File Paths & Emails',
    noEmbeddedStrings: 'No embedded URLs, public IPs, file paths, emails, or code tokens found.',
    embeddedIpsTitle: 'Auto-Traced Public IPs Extracted From Image',
    originNoteTitle: 'Forensic Origin & Privacy Summary',
    rawTagsTitle: 'All Extracted EXIF / XMP / IPTC / ICC Tags',
    filterTagsPlaceholder: 'Filter extracted metadata tags...',
  },
  tabs: {
    attackers: 'Active Attackers',
    phishing: 'Phishing & Trap URLs',
    globalThreats: 'Global Threats',
    defenseCenter: 'Defense & System Shields',
  },
  tables: {
    ipAddress: 'IP / Port',
    threatType: 'Threat Classification',
    originLocation: 'Country & City',
    asnIsp: 'ASN & ISP',
    sourceFeed: 'Source Feed',
    actions: 'Defense Actions',
    traceOnRadar: 'Trace on Map',
    defendNow: 'Defend',
    defendedBadge: 'Shielded / Blocked',
    deepScan: 'Deep Scan',
    filterPlaceholder: 'Filter by IP, country, hacker campaign, or CVE...',
    phishWarningNote:
      'Warning: URLs below are live credential-stealing traps. Use Takedown & Sinkhole or Safe Scan without visiting them.',
    takedownDomainBtn: 'Block & Takedown',
    sinkholedBadge: 'Sinkholed',
    inspectSafely: 'Safe Scan',
    ransomwareLinked: 'Ransomware Linked',
    standardCve: 'Actively Exploited',
    addedDate: 'Date Added',
    countermeasureBtn: 'Investigate & Mitigate',
    inspectTarget: 'Scan Target',
    openReport: 'Source Report',
    feedHealthTitle: 'Live Threat Feed Status',
  },
  defense: {
    subtitle:
      'Deploy real Nginx/iptables/Cloudflare firewall rules, DNS phishing sinkholes, RDAP abuse takedown packets, and continuous 24/7 website defense watchdogs.',
    protectedWebsitesTitle: 'Protected Website & System Watchdog Shields',
    noShieldsYet: 'No website defense shields active yet — scan any site above to activate continuous protection.',
    blockedAttackersTitle: 'Blocked Attacker IPs & RDAP Abuse Takedowns',
    noBlockedIpsYet: 'No attacker IPs blocked yet — click Defend on any active attacker.',
    sinkholedDomainsTitle: 'Sinkholed Phishing Domains & Takedowns',
    noSinkholesYet: 'No phishing domains sinkholed yet — click Block & Takedown on any phishing trap.',
    firewallBundleTitle: 'Production Firewall & DNS Sinkhole Bundle',
    copyBtn: 'Copy',
    copiedBtn: 'Copied',
    recheckBtn: 'Re-Audit',
    removeBtn: 'Remove',
    reportAbuseEmailBtn: 'Email ISP Abuse',
    reportSafeBrowsingBtn: 'Report Safe Browsing',
    reportNetcraftBtn: 'Report Netcraft',
    statusShielded: 'Shielded (Watchdog Active)',
    statusAlert: 'Alert / Hardening Required',
  },
  severityLabels: {
    CRITICAL: 'CRITICAL THREAT',
    HIGH: 'HIGH RISK',
    ELEVATED: 'ELEVATED',
    CLEAN: 'VERIFIED CLEAN',
  },
};

export function getCyberTranslations(lang: Language): CyberTranslations {
  return lang === 'bn' ? bn : en;
}
