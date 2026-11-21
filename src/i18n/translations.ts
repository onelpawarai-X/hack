import type { Language } from '../types/intelligence';

export interface Translations {
  appName: string;
  topBar: {
    worldVerified: string;
    verifying: string;
    syncing: string;
    reverifyBtn: string;
    openBrowserBtn: string;
    cachedLabel: string;
    liveLabel: string;
    english: string;
    bengali: string;
  };
  browser: {
    title: string;
    subtitle: string;
    addressPlaceholder: string;
    goBtn: string;
    backBtn: string;
    forwardBtn: string;
    reloadBtn: string;
    openExternalBtn: string;
    closeBtn: string;
    browseInApp: string;
    loadingPage: string;
    searchModeLabel: string;
    pageModeLabel: string;
    linksTitle: string;
    quickSitesLabel: string;
    quickSites: Array<{ label: string; target: string }>;
  };
  briefing: {
    title: string;
    subtitle: string;
    whatHappened: string;
    globalImpact: string;
    sectorBreakdown: string;
    citationsTitle: string;
    searchQueriesTitle: string;
    impactLabels: {
      High: string;
      Elevated: string;
      Moderate: string;
    };
    errorTitle: string;
    retry: string;
  };
  markets: {
    title: string;
    subtitle: string;
    macroBriefTitle: string;
    equitiesTitle: string;
    cryptoTitle: string;
    fxTitle: string;
    colAsset: string;
    colSymbol: string;
    colPrice: string;
    colChange: string;
    colAsOf: string;
    colSource: string;
    unavailable: string;
    citationsTitle: string;
  };
  research: {
    title: string;
    subtitle: string;
    filterAll: string;
    filterAi: string;
    filterScience: string;
    filterEcon: string;
    filterBiomed: string;
    aiSummarize: string;
    summarizing: string;
    hideSummary: string;
    plainSummary: string;
    keyTakeaways: string;
    significance: string;
    openPaper: string;
    emptyState: string;
  };
  news: {
    title: string;
    subtitle: string;
    filterAll: string;
    verifyAnalyze: string;
    verifying: string;
    hideVerification: string;
    verdictLabels: {
      Confirmed: string;
      Developing: string;
      'Mixed Reports': string;
      Unverified: string;
    };
    multiOutletAnalysis: string;
    verifiedFacts: string;
    caveats: string;
    readOriginal: string;
    emptyState: string;
  };
  explore: {
    title: string;
    subtitle: string;
    inputPlaceholder: string;
    submitBtn: string;
    searching: string;
    quickPromptsLabel: string;
    quickPrompts: string[];
    dossierTitle: string;
    keyFindings: string;
    worldBankTitle: string;
    colIndicator: string;
    colValue: string;
    colYear: string;
    colUnit: string;
    wikiTitle: string;
    wikidataTitle: string;
    dataGapsTitle: string;
    citationsTitle: string;
  };
  common: {
    loadingData: string;
    noCitations: string;
    apiNotice: string;
  };
}

export const TRANSLATIONS: Record<Language, Translations> = {
  en: {
    appName: 'OmniGlobe Daily',
    topBar: {
      worldVerified: 'World Verified',
      verifying: 'Syncing World Data',
      syncing: 'Syncing Status',
      reverifyBtn: 'Re-Verify World Data Now',
      openBrowserBtn: 'Web Browser',
      cachedLabel: '15m Cache',
      liveLabel: 'Live Open Feed',
      english: 'English',
      bengali: 'বাংলা',
    },
    browser: {
      title: 'Built-In Web Browser',
      subtitle:
        'Browse any website URL or search the live web directly inside this workspace with zero external keys.',
      addressPlaceholder:
        'Enter any URL (e.g., bbc.com/news, en.wikipedia.org/wiki/Bangladesh) or search topic...',
      goBtn: 'Go / Search',
      backBtn: 'Back',
      forwardBtn: 'Forward',
      reloadBtn: 'Reload',
      openExternalBtn: 'Open Tab',
      closeBtn: 'Close Browser',
      browseInApp: 'Browse In-App',
      loadingPage: 'Fetching live web page...',
      searchModeLabel: 'Live Web Search',
      pageModeLabel: 'Readable Web Page',
      linksTitle: 'Links & Search Results (Click to Open Inside Browser)',
      quickSitesLabel: 'Quick Launch',
      quickSites: [
        { label: 'BBC World', target: 'https://www.bbc.com/news/world' },
        { label: 'UN News', target: 'https://news.un.org/en/' },
        { label: 'Wikipedia: World Economy', target: 'https://en.wikipedia.org/wiki/World_economy' },
        { label: 'arXiv CS.AI', target: 'https://arxiv.org/list/cs.AI/recent' },
      ],
    },
    briefing: {
      title: 'Daily World Briefing',
      subtitle:
        'Automatic keyless synthesis across Geopolitics, Global Economy, AI & Technology, Climate, and Energy.',
      whatHappened: 'What Happened Today',
      globalImpact: 'Global Impact Analysis',
      sectorBreakdown: 'Domain Intelligence Matrix',
      citationsTitle: 'Verified Live Sources',
      searchQueriesTitle: 'Monitored Global Topics',
      impactLabels: {
        High: 'High Impact',
        Elevated: 'Elevated',
        Moderate: 'Moderate',
      },
      errorTitle: 'Unable to load World Briefing',
      retry: 'Retry Verification',
    },
    markets: {
      title: 'Global Markets & Macroeconomics',
      subtitle:
        'Live equities & commodities (Yahoo Finance & DSEBD), digital assets (CoinGecko), and global FX including USD/BDT.',
      macroBriefTitle: 'Daily Market Sentiment & Macro Brief',
      equitiesTitle: 'Equities & Commodities (Live Charts)',
      cryptoTitle: 'Digital Assets (CoinGecko Live)',
      fxTitle: 'Global Currencies vs USD (Live FX)',
      colAsset: 'Instrument',
      colSymbol: 'Ticker',
      colPrice: 'Price / Rate',
      colChange: '24h / Change',
      colAsOf: 'Session / As Of',
      colSource: 'Feed Source',
      unavailable: 'Unavailable',
      citationsTitle: 'Market Data Sources',
    },
    research: {
      title: 'Daily Research Papers & Breakthroughs',
      subtitle:
        'Live publications from arXiv, Crossref, and PubMed with instant plain-language summary and in-app reading.',
      filterAll: 'All Domains',
      filterAi: 'AI & Tech',
      filterScience: 'Physics & Science',
      filterEcon: 'Economics',
      filterBiomed: 'Biomedical',
      aiSummarize: 'Summarize',
      summarizing: 'Extracting...',
      hideSummary: 'Hide Summary',
      plainSummary: 'Plain-Language Summary',
      keyTakeaways: 'Key Takeaways',
      significance: 'Publication Context',
      openPaper: 'Source Link',
      emptyState: 'No papers matched the selected domain filter.',
    },
    news: {
      title: 'Global News Wire & Fact-Verifier',
      subtitle:
        'Live dispatches from BBC World, Al Jazeera, TechCrunch, UN News, and Bing Global Search with multi-outlet cross-checking.',
      filterAll: 'All Wires',
      verifyAnalyze: 'Verify & Analyze',
      verifying: 'Cross-checking...',
      hideVerification: 'Close Analysis',
      verdictLabels: {
        Confirmed: 'Confirmed Across Outlets',
        Developing: 'Developing Story',
        'Mixed Reports': 'Mixed Reports',
        Unverified: 'Sparse Corroboration',
      },
      multiOutletAnalysis: 'Multi-Outlet Cross-Check',
      verifiedFacts: 'Corroborated Dispatches',
      caveats: 'Verification Scope',
      readOriginal: 'Source Link',
      emptyState: 'No headlines available for the selected wire.',
    },
    explore: {
      title: 'Verify Anything & Browse Web',
      subtitle:
        'Query any country, company, or dataset across World Bank Open Data, Wikipedia, Wikidata, and Live Web Search — zero API keys needed.',
      inputPlaceholder:
        'Verify any country, company, or topic (e.g., Bangladesh GDP & inflation, Nvidia semiconductor market)...',
      submitBtn: 'Verify Query',
      searching: 'Verifying...',
      quickPromptsLabel: 'Sample Probes',
      quickPrompts: [
        'Bangladesh GDP, inflation and economy',
        'United States interest rates and inflation',
        'Nvidia semiconductor market position',
        'Global renewable energy capacity',
      ],
      dossierTitle: 'Verified Intelligence Dossier',
      keyFindings: 'Verified Key Findings',
      worldBankTitle: 'World Bank Open Data Indicators',
      colIndicator: 'Indicator',
      colValue: 'Latest Value',
      colYear: 'Year',
      colUnit: 'Unit',
      wikiTitle: 'Wikipedia Reference',
      wikidataTitle: 'Wikidata Identifier',
      dataGapsTitle: 'Data Availability & Scope',
      citationsTitle: 'Verified Web Citations',
    },
    common: {
      loadingData: 'Verifying live global datasets...',
      noCitations: 'No external web citations returned for this query.',
      apiNotice: 'Upstream Feed Notice',
    },
  },
  bn: {
    appName: 'অমনিগ্লোব ডেইলি',
    topBar: {
      worldVerified: 'বিশ্ব তথ্য যাচাইকৃত',
      verifying: 'তথ্য যাচাই চলছে',
      syncing: 'তথ্য সমন্বয় হচ্ছে',
      reverifyBtn: 'এখনই পুনরায় যাচাই করুন',
      openBrowserBtn: 'ওয়েব ব্রাউজার',
      cachedLabel: '১৫ মি. ক্যাশ',
      liveLabel: 'সরাসরি ওপেন ফিড',
      english: 'English',
      bengali: 'বাংলা',
    },
    browser: {
      title: 'বিল্ট-ইন ওয়েব ব্রাউজার',
      subtitle:
        'কোনো API কী ছাড়াই সরাসরি এই অ্যাপের ভেতর থেকেই যেকোনো ওয়েবসাইট ব্রাউজ বা ওয়েব অনুসন্ধান করুন।',
      addressPlaceholder:
        'যেকোনো ওয়েবসাইট লিংক (যেমন: bbc.com/news) অথবা অনুসন্ধানের বিষয় লিখুন...',
      goBtn: 'যান / খুঁজুন',
      backBtn: 'পেছনে',
      forwardBtn: 'সামনে',
      reloadBtn: 'রিলোড',
      openExternalBtn: 'নতুন ট্যাব',
      closeBtn: 'ব্রাউজার বন্ধ',
      browseInApp: 'অ্যাপে ব্রাউজ করুন',
      loadingPage: 'ওয়েব পেজ লোড হচ্ছে...',
      searchModeLabel: 'লাইভ ওয়েব অনুসন্ধান',
      pageModeLabel: 'ওয়েব পেজ ভিউ',
      linksTitle: 'লিংক ও ফলাফল (অ্যাপের ভেতরে খুলতে ক্লিক করুন)',
      quickSitesLabel: 'দ্রুত ভিজিট',
      quickSites: [
        { label: 'BBC World', target: 'https://www.bbc.com/news/world' },
        { label: 'UN News', target: 'https://news.un.org/en/' },
        { label: 'উইকিপিডিয়া: বিশ্ব অর্থনীতি', target: 'https://bn.wikipedia.org/wiki/%E0%A6%AC%E0%A6%BF%E0%A6%B6%E0%A7%8D%E0%A6%AC_%E0%A6%85%E0%A6%B0%E0%A7%8D%E0%A6%A5%E0%A6%A8%E0%A7%80%E0%A6%A4%E0%A6%BF' },
        { label: 'arXiv CS.AI', target: 'https://arxiv.org/list/cs.AI/recent' },
      ],
    },
    briefing: {
      title: 'দৈনিক বিশ্ব ব্রিফিং',
      subtitle:
        'কোনো API কী ছাড়াই স্বয়ংক্রিয়ভাবে ভূ-রাজনীতি, অর্থনীতি, এআই ও প্রযুক্তি, জলবায়ু এবং জ্বালানির লাইভ সারসংক্ষেপ।',
      whatHappened: 'আজ বিশ্বে যা ঘটেছে',
      globalImpact: 'বৈশ্বিক প্রভাব বিশ্লেষণ',
      sectorBreakdown: 'খাতভিত্তিক গোয়েন্দা বিশ্লেষণ',
      citationsTitle: 'যাচাইকৃত লাইভ তথ্যসূত্র',
      searchQueriesTitle: 'পর্যবেক্ষণকৃত বৈশ্বিক বিষয়',
      impactLabels: {
        High: 'উচ্চ প্রভাব',
        Elevated: 'উল্লেখযোগ্য',
        Moderate: 'মাঝারি',
      },
      errorTitle: 'বিশ্ব ব্রিফিং লোড করা যায়নি',
      retry: 'পুনরায় চেষ্টা করুন',
    },
    markets: {
      title: 'বৈশ্বিক বাজার ও সামষ্টিক অর্থনীতি',
      subtitle:
        'লাইভ শেয়ার সূচক ও পণ্য বাজার (Yahoo Finance ও DSEBD), ক্রিপ্টো (CoinGecko) এবং USD/BDT সহ বৈশ্বিক মুদ্রা বিনিময় হার।',
      macroBriefTitle: 'দৈনিক বাজার প্রবণতা ও সামষ্টিক বিশ্লেষণ',
      equitiesTitle: 'শেয়ার সূচক ও পণ্য বাজার (লাইভ চার্ট)',
      cryptoTitle: 'ডিজিটাল অ্যাসেট (CoinGecko লাইভ)',
      fxTitle: 'বৈশ্বিক মুদ্রা বিনিময় হার বনাম USD',
      colAsset: 'সূচক / সম্পদ',
      colSymbol: 'প্রতীক',
      colPrice: 'মূল্য / হার',
      colChange: '২৪ ঘণ্টা / পরিবর্তন',
      colAsOf: 'সেশন / সময়',
      colSource: 'তথ্য উৎস',
      unavailable: 'তথ্য অনুপলব্ধ',
      citationsTitle: 'বাজার তথ্য সূত্র',
    },
    research: {
      title: 'দৈনিক গবেষণাপত্র ও বৈজ্ঞানিক অগ্রগতি',
      subtitle:
        'arXiv, Crossref এবং PubMed থেকে সাম্প্রতিক প্রকাশিত গবেষণা—সহজ সারসংক্ষেপ ও অ্যাপের ভেতরেই পড়ার সুবিধা।',
      filterAll: 'সকল খাত',
      filterAi: 'এআই ও প্রযুক্তি',
      filterScience: 'পদার্থবিজ্ঞান ও বিজ্ঞান',
      filterEcon: 'অর্থনীতি',
      filterBiomed: 'চিকিৎসা ও জীববিজ্ঞান',
      aiSummarize: 'সারসংক্ষেপ',
      summarizing: 'বিশ্লেষণ চলছে...',
      hideSummary: 'সারসংক্ষেপ লুকান',
      plainSummary: 'সহজ ভাষায় সারসংক্ষেপ',
      keyTakeaways: 'গুরুত্বপূর্ণ দিকসমূহ',
      significance: 'প্রকাশনার প্রেক্ষাপট',
      openPaper: 'মূল উৎস',
      emptyState: 'নির্বাচিত বিভাগে কোনো গবেষণাপত্র পাওয়া যায়নি।',
    },
    news: {
      title: 'বৈশ্বিক সংবাদ প্রবাহ ও ফ্যাক্ট-ভেরিফায়ার',
      subtitle:
        'BBC World, Al Jazeera, TechCrunch, UN News এবং Bing গ্লোবাল সার্চ থেকে সরাসরি সংবাদ ও বহু-উৎস যাচাই।',
      filterAll: 'সকল মাধ্যম',
      verifyAnalyze: 'যাচাই ও বিশ্লেষণ',
      verifying: 'তথ্য যাচাই চলছে...',
      hideVerification: 'বিশ্লেষণ বন্ধ করুন',
      verdictLabels: {
        Confirmed: 'একাধিক সূত্রে নিশ্চিত',
        Developing: 'চলমান ঘটনা',
        'Mixed Reports': 'মিশ্র প্রতিবেদন',
        Unverified: 'সীমিত সূত্র',
      },
      multiOutletAnalysis: 'বহু-মাধ্যম ক্রস-চেক বিশ্লেষণ',
      verifiedFacts: 'নিশ্চিতকৃত সংবাদসমূহ',
      caveats: 'যাচাইয়ের পরিধি',
      readOriginal: 'মূল প্রতিবেদন',
      emptyState: 'নির্বাচিত মাধ্যমে কোনো শিরোনাম পাওয়া যায়নি।',
    },
    explore: {
      title: 'যেকোনো তথ্য যাচাই ও ওয়েব ব্রাউজ',
      subtitle:
        'কোনো API কী ছাড়াই বিশ্বব্যাংক ওপেন ডেটা, উইকিপিডিয়া, উইকিডেটা এবং লাইভ ওয়েব অনুসন্ধানের মাধ্যমে যেকোনো দেশ বা বিষয় যাচাই করুন।',
      inputPlaceholder:
        'যেকোনো দেশ, কোম্পানি বা বিষয় লিখুন (যেমন: Bangladesh GDP and inflation)...',
      submitBtn: 'তথ্য যাচাই করুন',
      searching: 'যাচাই চলছে...',
      quickPromptsLabel: 'নমুনা অনুসন্ধান',
      quickPrompts: [
        'Bangladesh GDP, inflation and economy',
        'United States interest rates and inflation',
        'Nvidia semiconductor market position',
        'Global renewable energy capacity',
      ],
      dossierTitle: 'যাচাইকৃত গোয়েন্দা ডসিয়ার',
      keyFindings: 'যাচাইকৃত মূল তথ্যসমূহ',
      worldBankTitle: 'বিশ্বব্যাংক ওপেন ডেটা সূচক',
      colIndicator: 'সূচক',
      colValue: 'সর্বশেষ মান',
      colYear: 'বছর',
      colUnit: 'একক',
      wikiTitle: 'উইকিপিডিয়া তথ্যসূত্র',
      wikidataTitle: 'উইকিডেটা পরিচিতি',
      dataGapsTitle: 'তথ্যের প্রাপ্যতা ও পরিধি',
      citationsTitle: 'যাচাইকৃত ওয়েব তথ্যসূত্র',
    },
    common: {
      loadingData: 'বৈশ্বিক লাইভ তথ্য যাচাই করা হচ্ছে...',
      noCitations: 'এই অনুসন্ধানের জন্য কোনো বহিরাগত ওয়েব সূত্র পাওয়া যায়নি।',
      apiNotice: 'উৎস ফিড সতর্কতা',
    },
  },
};
