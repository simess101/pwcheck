export type Entry = { site: string; username: string; password: string };

export type WeakFinding = {
  index: number;
  site: string;
  username: string;
  reasons: string[];
};

export type ReuseGroup = {
  count: number;
  sites: { site: string; username: string }[];
};

export type Report = {
  summary: {
    total: number;
    weak: number;
    reusedGroups: number;
    reusedAccounts: number;
  };
  weakFindings: WeakFinding[];
  reuseGroups: ReuseGroup[];
};


function hasLower(s: string) { return /[a-z]/.test(s); }
function hasUpper(s: string) { return /[A-Z]/.test(s); }
function hasDigit(s: string) { return /\d/.test(s); }
function hasSymbol(s: string) { return /[^A-Za-z0-9]/.test(s); }

export function analyze(entries: Entry[]): Report {
  // Weak checks
  const weakFindings: WeakFinding[] = entries.map((e, idx) => {
    const pw = e.password ?? "";
    const reasons: string[] = [];

    if (pw.length < 12) reasons.push("Length < 12");
    if (!hasLower(pw)) reasons.push("No lowercase");
    if (!hasUpper(pw)) reasons.push("No uppercase");
    if (!hasDigit(pw)) reasons.push("No number");
    if (!hasSymbol(pw)) reasons.push("No symbol");
    if (/password|qwerty|1234/i.test(pw)) reasons.push("Common pattern");

    return reasons.length
      ? { index: idx, site: e.site, username: e.username, reasons }
      : null;
  }).filter((x): x is WeakFinding => x !== null);

  // Reuse detection (plaintext grouping for now; later we’ll hash)
  const map = new Map<string, { site: string; username: string }[]>();
  for (const e of entries) {
    const key = e.password ?? "";
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push({ site: e.site, username: e.username });
  }

  const reuseGroups: ReuseGroup[] = [];
  for (const [, sites] of map) {
    if (sites.length >= 2) reuseGroups.push({ count: sites.length, sites });
  }
  reuseGroups.sort((a, b) => b.count - a.count);

  const reusedGroups = reuseGroups.length;
const reusedAccounts = reuseGroups.reduce((acc, g) => acc + g.count, 0);

return {
  summary: {
    total: entries.length,
    weak: weakFindings.length,
    reusedGroups,
    reusedAccounts
  },
  weakFindings,
  reuseGroups
};
}
