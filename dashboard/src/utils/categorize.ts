const DOMAIN_CATEGORIES: Record<string, string[]> = {
  "Social media": ["facebook", "instagram", "twitter", "tiktok", "snapchat"],
  Streaming: ["netflix", "youtube", "spotify", "disney", "amazon"],
  Gaming: ["xbox", "playstation", "steam", "epicgames"],
  "IoT/Smart home": ["ring", "dreame", "xiaomi", "tuya", "alexa"],
  Advertising: ["doubleclick", "googlesyndication", "adnxs", "tracking"],
  "Apple services": ["apple", "icloud", "itunes"],
  Microsoft: ["microsoft", "windows", "azure"],
};

export function categorizeDomain(domain: string): string {
  const domainLower = domain.toLowerCase();
  for (const [category, keywords] of Object.entries(DOMAIN_CATEGORIES)) {
    for (const keyword of keywords) {
      if (domainLower.includes(keyword)) {
        return category;
      }
    }
  }
  return "Other";
}
