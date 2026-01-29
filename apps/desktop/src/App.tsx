import React, { useMemo, useRef, useState } from "react";
import Papa from "papaparse";
import { analyze, type Entry } from "@pwcheck/core";

type Row = {
  name: string;
  url: string;
  username: string;
  password: string;
  note: string;
};

type ParseResult =
  | { ok: true; rows: Row[]; entries: Entry[] }
  | { ok: false; error: string };

function parseCSV(text: string): ParseResult {
  const parsed = Papa.parse<Row>(text, {
    header: true,
    skipEmptyLines: true,
    transformHeader: (h) => h.trim().toLowerCase(),
  });

  if (parsed.errors?.length) {
    return { ok: false, error: parsed.errors[0].message };
  }

  const fields = parsed.meta.fields ?? [];
  const required = ["name", "url", "username", "password", "note"] as const;
  const missing = required.filter((k) => !fields.includes(k));

  if (missing.length) {
    return {
      ok: false,
      error: `Missing required columns: ${missing.join(", ")}. Found: ${fields.join(", ")}`,
    };
  }

  const data = parsed.data ?? [];
  const rows: Row[] = data.map((r) => ({
    name: (r.name ?? "").trim(),
    url: (r.url ?? "").trim(),
    username: (r.username ?? "").trim(),
    password: (r.password ?? "").trim(),
    note: (r.note ?? "").trim(),
  }));

  const entries: Entry[] = rows
    .map((r) => ({
      site: r.name || r.url || "(unknown)",
      username: r.username,
      password: r.password,
    }))
    .filter((e) => e.site || e.username || e.password);

  return { ok: true, rows, entries };
}

async function readFileText(file: File): Promise<string> {
  return await file.text();
}

function keyOf(site: string, username: string) {
  return `${site}||${username}`;
}

function asDomainLabel(site: string) {
  try {
    if (/^https?:\/\//i.test(site)) {
      const u = new URL(site);
      return u.hostname || site;
    }
  } catch {
    // ignore
  }
  return site;
}

type IssueMode = "all" | "reuse" | "weak";
type SortMode = "risk" | "domain" | "reuseCount";

function isDevUrl(url: string) {
  const devUrlRegex =
    /(^https?:\/\/localhost\b)|(^https?:\/\/127\.0\.0\.1\b)|(^https?:\/\/0\.0\.0\.0\b)|(^https?:\/\/192\.168\.)|(^https?:\/\/10\.)|(^https?:\/\/172\.(1[6-9]|2\d|3[0-1])\.)/i;
  return devUrlRegex.test(url);
}

function riskLabel(reuseCount: number, isWeak: boolean) {
  if (reuseCount >= 10 && isWeak) return "HIGH";
  if (reuseCount >= 2 && isWeak) return "MEDIUM";
  if (reuseCount >= 10) return "MEDIUM";
  if (isWeak) return "MEDIUM";
  return "LOW";
}

function riskScore(reuseCount: number, isWeak: boolean) {
  return reuseCount * 10 + (isWeak ? 15 : 0);
}

function adjustWeakReasons(
  coreReasons: string[],
  password: string | undefined,
  minLength: number
) {
  const reasons = Array.isArray(coreReasons) ? coreReasons.slice() : [];
  const pwLen = password?.length ?? 0;

  // Remove any length reason; we'll re-evaluate with the UI policy.
  const out: string[] = [];
  for (const r of reasons) {
    if (r.toLowerCase().startsWith("length")) continue;
    out.push(r);
  }

  // Add normalized length reason if needed.
  if (password && pwLen > 0 && pwLen < minLength) {
    out.unshift(`Length < ${minLength}`);
  }

  return out;
}

function fixTextFor(reuseCount: number, reasons: string[], minLength: number) {
  const fixes: string[] = [];

  if (reuseCount >= 2) {
    fixes.push(
      `Change this password so it is unique (currently reused across ${reuseCount} accounts).`
    );
  }

  if (reasons.some((r) => r.toLowerCase().startsWith("length"))) {
    fixes.push(`Update to at least ${minLength} characters.`);
  }
  if (reasons.some((r) => r.toLowerCase().includes("no uppercase"))) {
    fixes.push("Add at least one uppercase letter.");
  }
  if (reasons.some((r) => r.toLowerCase().includes("no lowercase"))) {
    fixes.push("Add at least one lowercase letter.");
  }
  if (reasons.some((r) => r.toLowerCase().includes("no number"))) {
    fixes.push("Add at least one number.");
  }
  if (reasons.some((r) => r.toLowerCase().includes("no symbol"))) {
    fixes.push("Add at least one symbol.");
  }
  if (reasons.some((r) => r.toLowerCase().includes("common pattern"))) {
    fixes.push("Avoid common patterns (dictionary words, predictable substitutions, repeats).");
  }

  if (!fixes.length) fixes.push("No action needed based on current checks.");

  return fixes;
}

export default function App() {
  const [fileName, setFileName] = useState<string>("");
  const [rawText, setRawText] = useState<string>("");
  const [error, setError] = useState<string>("");

  const [ignoreDevUrls, setIgnoreDevUrls] = useState<boolean>(true);
  const [minLength, setMinLength] = useState<number>(12);

  const [query, setQuery] = useState<string>("");
  const [issueMode, setIssueMode] = useState<IssueMode>("all");
  const [sortMode, setSortMode] = useState<SortMode>("risk");

  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [showCsvPreview, setShowCsvPreview] = useState<boolean>(false); // OFF by default
  const [demoMode, setDemoMode] = useState<boolean>(false); // OFF by default

  const inputRef = useRef<HTMLInputElement | null>(null);

  const parsed = useMemo(() => {
    if (!rawText) return null;
    return parseCSV(rawText);
  }, [rawText]);

  const rows = useMemo(() => (parsed && parsed.ok ? parsed.rows : []), [parsed]);

  const entries = useMemo(() => {
    if (!parsed || !parsed.ok) return [];

    return parsed.entries.filter((e) => {
      if (!e.password || e.password.trim().length === 0) return false;

      if (ignoreDevUrls) {
        const row = rows.find((r) => (r.name || r.url) === e.site);
        if (row?.url && isDevUrl(row.url)) return false;
      }
      return true;
    });
  }, [parsed, ignoreDevUrls, rows]);

  const report = useMemo(() => analyze(entries), [entries]);

  function rowBySite(site: string) {
    return rows.find((r) => (r.name || r.url) === site) ?? null;
  }

  const passwordByKey = useMemo(() => {
    const map = new Map<string, string>();
    for (const e of entries) {
      map.set(keyOf(e.site, e.username), e.password);
    }
    return map;
  }, [entries]);

  const reuseCountByKey = useMemo(() => {
    const map = new Map<string, number>();
    const groups: any[] = (report as any).reuseGroups ?? [];
    for (const g of groups) {
      const cnt = Number(g?.count ?? 0);
      const sites = Array.isArray(g?.sites) ? g.sites : [];
      for (const s of sites) {
        const k = keyOf(String(s.site ?? ""), String(s.username ?? ""));
        if (k !== "||") map.set(k, cnt);
      }
    }
    return map;
  }, [report]);

  const weakAdjustedByKey = useMemo(() => {
    const map = new Map<string, { reasons: string[] }>();
    const wf: any[] = (report as any).weakFindings ?? [];
    for (const w of wf) {
      const site = String(w?.site ?? "");
      const username = String(w?.username ?? "");
      const k = keyOf(site, username);
      const pw = passwordByKey.get(k);
      const reasons = adjustWeakReasons(w?.reasons ?? [], pw, minLength);
      if (reasons.length) map.set(k, { reasons });
    }
    return map;
  }, [report, passwordByKey, minLength]);

  type ResultRow = {
    key: string;
    site: string;
    domain: string;
    username: string;
    url?: string;
    reuseCount: number;
    weakReasons: string[];
    isWeak: boolean;
    risk: "LOW" | "MEDIUM" | "HIGH";
  };

  // Demo masking helpers
  const maskDomain = (domain: string) => {
    if (!demoMode) return domain;
    // Keep TLD, mask the rest
    const parts = domain.split(".");
    if (parts.length <= 1) return "site.example";
    const tld = parts[parts.length - 1];
    return `site.${tld}`;
  };

  const maskUrl = (url: string) => {
    if (!demoMode) return url;
    try {
      const u = new URL(url);
      // Keep scheme + hostname-ish placeholder
      return `${u.protocol}//${maskDomain(u.hostname)}/…`;
    } catch {
      return "https://site.example/…";
    }
  };

  const maskUsername = (username: string) => {
    if (!demoMode) return username;
    if (!username) return "";
    // email? keep domain, mask local part
    const at = username.indexOf("@");
    if (at >= 0) {
      const dom = username.slice(at + 1) || "example.com";
      return `user@${dom}`;
    }
    return "user";
  };

  const allResults: ResultRow[] = useMemo(() => {
    const results: ResultRow[] = [];

    for (const e of entries) {
      const k = keyOf(e.site, e.username);
      const reuseCount = reuseCountByKey.get(k) ?? 0;
      const weak = weakAdjustedByKey.get(k);
      const weakReasons = weak?.reasons ?? [];
      const isWeak = weakReasons.length > 0;

      if (issueMode === "reuse" && reuseCount < 2) continue;
      if (issueMode === "weak" && !isWeak) continue;

      const r = rowBySite(e.site);
      const url = r?.url || undefined;

      const q = query.trim().toLowerCase();
      if (q) {
        const hay = `${asDomainLabel(e.site)} ${e.site} ${e.username} ${url ?? ""}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }

      const risk = riskLabel(reuseCount, isWeak);
      results.push({
        key: k,
        site: e.site,
        domain: asDomainLabel(e.site),
        username: e.username,
        url,
        reuseCount,
        weakReasons,
        isWeak,
        risk,
      });
    }

    results.sort((a, b) => {
      if (sortMode === "domain") return a.domain.localeCompare(b.domain);
      if (sortMode === "reuseCount") return b.reuseCount - a.reuseCount;
      return riskScore(b.reuseCount, b.isWeak) - riskScore(a.reuseCount, a.isWeak);
    });

    return results;
  }, [entries, reuseCountByKey, weakAdjustedByKey, issueMode, sortMode, query, rows]);

  const derivedSummary = useMemo(() => {
    const total = entries.length;
    const weak = Array.from(weakAdjustedByKey.keys()).length;
    const reuseGroups = ((report as any).reuseGroups?.length ?? 0) as number;

    let reusedAccounts = 0;
    for (const e of entries) {
      const k = keyOf(e.site, e.username);
      if ((reuseCountByKey.get(k) ?? 0) >= 2) reusedAccounts++;
    }

    return { total, weak, reuseGroups, reusedAccounts };
  }, [entries, weakAdjustedByKey, report, reuseCountByKey]);

  const [selectedKey, setSelectedKey] = useState<string>("");
  const selected = useMemo(() => {
    return allResults.find((r) => r.key === selectedKey) ?? null;
  }, [allResults, selectedKey]);

  async function handleFile(file: File) {
    setError("");
    setFileName(file.name);

    try {
      const text = await readFileText(file);
      setRawText(text);

      const res = parseCSV(text);
      if (!res.ok) setError(res.error);

      setSelectedKey("");
    } catch (e: any) {
      setError(e?.message ?? "Failed to read file.");
    }
  }

  async function onPickFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    await handleFile(file);
    e.target.value = "";
  }

  function onDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) void handleFile(file);
  }

  function onDragOver(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
  }

  const selectedFixes = useMemo(() => {
    if (!selected) return [];
    return fixTextFor(selected.reuseCount, selected.weakReasons, minLength);
  }, [selected, minLength]);

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        overflowX: "hidden",
        background: "#0b0b0b",
        color: "#eaeaea",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
      }}
    >
      <style>{`
        @media (max-width: 980px) {
          .pw-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>

      <div style={{ padding: 18, paddingBottom: 12, flex: "0 0 auto" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 22, letterSpacing: 0.2 }}>pwcheck</h1>
          <div style={{ opacity: 0.8, fontSize: 13 }}>
            Runs locally in your browser (no server). Passwords are never displayed.
          </div>
        </div>

        <div
          onDrop={onDrop}
          onDragOver={onDragOver}
          style={{
            marginTop: 12,
            border: "1px dashed #2b2b2b",
            borderRadius: 14,
            padding: 14,
            background: "rgba(255,255,255,0.02)",
          }}
        >
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <input
              ref={inputRef}
              type="file"
              accept=".csv,text/csv"
              onChange={onPickFile}
              style={{ color: "#ddd" }}
            />
            <div style={{ opacity: 0.85 }}>
              {fileName ? (
                <>
                  Loaded: <b>{fileName}</b> ({entries.length} rows after filters)
                </>
              ) : (
                "Drag and drop a .csv here, or choose a file."
              )}
            </div>
          </div>

          <div style={{ marginTop: 10, display: "flex", gap: 16, flexWrap: "wrap" }}>
            <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={ignoreDevUrls}
                onChange={(e) => setIgnoreDevUrls(e.target.checked)}
              />
              Ignore local/dev URLs
            </label>

            <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
              Min length:
              <input
                type="number"
                value={minLength}
                min={6}
                max={64}
                onChange={(e) => setMinLength(Number(e.target.value || 12))}
                style={{
                  width: 72,
                  padding: "6px 8px",
                  borderRadius: 10,
                  border: "1px solid #2b2b2b",
                  background: "#111",
                  color: "#eee",
                }}
              />
            </label>

            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search domain / site / username"
              style={{
                flex: "1 1 280px",
                minWidth: 0,
                padding: "8px 10px",
                borderRadius: 12,
                border: "1px solid #2b2b2b",
                background: "#111",
                color: "#eee",
              }}
            />

            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                Issues:
                <select
                  value={issueMode}
                  onChange={(e) => setIssueMode(e.target.value as IssueMode)}
                  style={{
                    padding: "8px 10px",
                    borderRadius: 12,
                    border: "1px solid #2b2b2b",
                    background: "#111",
                    color: "#eee",
                  }}
                >
                  <option value="all">All issues</option>
                  <option value="reuse">Reuse only</option>
                  <option value="weak">Weak only</option>
                </select>
              </label>

              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                Sort:
                <select
                  value={sortMode}
                  onChange={(e) => setSortMode(e.target.value as SortMode)}
                  style={{
                    padding: "8px 10px",
                    borderRadius: 12,
                    border: "1px solid #2b2b2b",
                    background: "#111",
                    color: "#eee",
                  }}
                >
                  <option value="risk">Risk</option>
                  <option value="reuseCount">Reuse count</option>
                  <option value="domain">Domain</option>
                </select>
              </label>
            </div>
          </div>

          {error && <div style={{ marginTop: 10, color: "#ff9f9f" }}>{error}</div>}
        </div>

        <div
          style={{
            marginTop: 12,
            display: "grid",
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: 12,
          }}
        >
          {[
            { label: "Total accounts", value: derivedSummary.total },
            { label: "Weak", value: derivedSummary.weak },
            { label: "Reuse groups", value: derivedSummary.reuseGroups },
            { label: "Accounts reused", value: derivedSummary.reusedAccounts },
          ].map((c) => (
            <div
              key={c.label}
              style={{
                border: "1px solid #1f1f1f",
                borderRadius: 16,
                padding: 14,
                background: "rgba(255,255,255,0.02)",
                minHeight: 66,
              }}
            >
              <div style={{ fontSize: 12, opacity: 0.75 }}>{c.label}</div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>{c.value}</div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 10 }}>
          <button
            onClick={() => setShowAdvanced((v) => !v)}
            style={{
              background: "transparent",
              border: "1px solid #2b2b2b",
              color: "#ddd",
              padding: "8px 10px",
              borderRadius: 12,
              cursor: "pointer",
            }}
          >
            {showAdvanced ? "Hide advanced" : "Show advanced"}
          </button>

          {showAdvanced && (
            <div style={{ marginTop: 10, display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" }}>
              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={demoMode}
                  onChange={(e) => setDemoMode(e.target.checked)}
                />
                Demo mode (mask domains and usernames)
              </label>

              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={showCsvPreview}
                  onChange={(e) => setShowCsvPreview(e.target.checked)}
                />
                Show raw CSV preview
              </label>

              <div style={{ opacity: 0.7, fontSize: 12 }}>
                Use only for debugging parser issues. Avoid sharing screenshots when enabled.
              </div>
            </div>
          )}
        </div>
      </div>

      <div
        className="pw-grid"
        style={{
          flex: "1 1 auto",
          minHeight: 0,
          padding: 18,
          paddingTop: 8,
          paddingBottom: 28,
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) minmax(280px, 340px)",
          gap: 12,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            border: "1px solid #1f1f1f",
            borderRadius: 16,
            background: "rgba(255,255,255,0.02)",
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
            minWidth: 0,
          }}
        >
          <div style={{ padding: 14, borderBottom: "1px solid #1f1f1f" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
              <div style={{ fontWeight: 700 }}>Results ({allResults.length})</div>
              <div style={{ opacity: 0.75, fontSize: 12 }}>Click a row to view details</div>
            </div>

            <div
              style={{
                marginTop: 10,
                display: "grid",
                gridTemplateColumns: "180px 1fr",
                gap: 10,
                opacity: 0.85,
                fontSize: 12,
              }}
            >
              <div>Flags</div>
              <div>Domain</div>
            </div>
          </div>

          <div style={{ flex: 1, overflow: "auto" }}>
            {allResults.map((r) => {
              const selectedRow = selectedKey === r.key;

              const flagPill = (text: string, border: string, color: string) => (
                <span
                  style={{
                    display: "inline-block",
                    padding: "3px 8px",
                    borderRadius: 999,
                    border: `1px solid ${border}`,
                    color,
                    fontSize: 12,
                    lineHeight: 1.3,
                    whiteSpace: "nowrap",
                  }}
                >
                  {text}
                </span>
              );

              const domainLabel = demoMode ? maskDomain(r.domain) : r.domain;
              const urlLabel = r.url ? (demoMode ? maskUrl(r.url) : r.url) : (demoMode ? maskUrl(r.site) : r.site);

              return (
                <div
                  key={r.key}
                  onClick={() => setSelectedKey(r.key)}
                  style={{
                    padding: 14,
                    borderBottom: "1px solid rgba(255,255,255,0.05)",
                    cursor: "pointer",
                    background: selectedRow ? "rgba(255,255,255,0.04)" : "transparent",
                    display: "grid",
                    gridTemplateColumns: "180px 1fr",
                    gap: 10,
                    alignItems: "center",
                  }}
                >
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {r.reuseCount >= 2
                      ? flagPill(`REUSED ×${r.reuseCount}`, "#7a5a2d", "#ffcc8a")
                      : null}
                    {r.isWeak ? flagPill("WEAK", "#2b6d3b", "#b7ffbf") : null}
                    {flagPill(
                      r.risk,
                      r.risk === "HIGH" ? "#8b2d2d" : "#333",
                      "#ffb3b3"
                    )}
                  </div>

                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 14 }}>{domainLabel}</div>
                    <div
                      style={{
                        opacity: 0.7,
                        fontSize: 12,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {urlLabel}
                    </div>
                  </div>
                </div>
              );
            })}

            {!allResults.length && (
              <div style={{ padding: 14, opacity: 0.75 }}>
                No results match the current filters.
              </div>
            )}
          </div>

          {showCsvPreview && (
            <div style={{ borderTop: "1px solid #1f1f1f", padding: 14 }}>
              <div style={{ fontWeight: 700, marginBottom: 8 }}>CSV preview (first 60 lines)</div>
              <textarea
                value={rawText ? rawText.split(/\r?\n/).slice(0, 60).join("\n") : ""}
                readOnly
                rows={10}
                style={{
                  width: "100%",
                  fontFamily: "monospace",
                  fontSize: 12,
                  background: "#0f0f0f",
                  color: "#ddd",
                  border: "1px solid #2b2b2b",
                  borderRadius: 12,
                  padding: 10,
                  resize: "vertical",
                }}
                placeholder="Upload a CSV to preview it here."
              />
              <div style={{ opacity: 0.65, marginTop: 8, fontSize: 12 }}>
                Parser: PapaParse (handles quoted commas correctly).
              </div>
            </div>
          )}
        </div>

        <div
          style={{
            border: "1px solid #1f1f1f",
            borderRadius: 16,
            background: "rgba(255,255,255,0.02)",
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
            minWidth: 0,
          }}
        >
          <div style={{ padding: 14, borderBottom: "1px solid #1f1f1f" }}>
            <div style={{ fontWeight: 700 }}>Details</div>
            <div style={{ opacity: 0.75, fontSize: 12, marginTop: 4 }}>
              {selected ? "Selected row" : "Select a row to view issues and fixes"}
            </div>
          </div>

          <div style={{ padding: 14, overflow: "auto" }}>
            {!selected ? (
              <div style={{ opacity: 0.75, fontSize: 13 }}>
                Click a result on the left to see what is wrong and what to fix.
              </div>
            ) : (
              <>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {selected.reuseCount >= 2 ? (
                    <span
                      style={{
                        display: "inline-block",
                        padding: "3px 8px",
                        borderRadius: 999,
                        border: "1px solid #7a5a2d",
                        color: "#ffcc8a",
                        fontSize: 12,
                      }}
                    >
                      REUSED ×{selected.reuseCount}
                    </span>
                  ) : null}
                  {selected.isWeak ? (
                    <span
                      style={{
                        display: "inline-block",
                        padding: "3px 8px",
                        borderRadius: 999,
                        border: "1px solid #2b6d3b",
                        color: "#b7ffbf",
                        fontSize: 12,
                      }}
                    >
                      WEAK
                    </span>
                  ) : null}
                  <span
                    style={{
                      display: "inline-block",
                      padding: "3px 8px",
                      borderRadius: 999,
                      border: "1px solid #8b2d2d",
                      color: "#ffb3b3",
                      fontSize: 12,
                    }}
                  >
                    {selected.risk}
                  </span>
                </div>

                <div style={{ marginTop: 10, fontWeight: 800, fontSize: 14 }}>
                  {demoMode ? maskDomain(selected.domain) : selected.domain}
                </div>

                <div style={{ marginTop: 8, fontSize: 12, opacity: 0.85, lineHeight: 1.45 }}>
                  <div>
                    <span style={{ opacity: 0.7 }}>Username:</span>{" "}
                    {demoMode ? maskUsername(selected.username) : selected.username}
                  </div>
                  {selected.url ? (
                    <div style={{ marginTop: 4 }}>
                      <span style={{ opacity: 0.7 }}>URL:</span>{" "}
                      {demoMode ? maskUrl(selected.url) : selected.url}
                    </div>
                  ) : null}
                </div>

                <div style={{ marginTop: 14 }}>
                  <div style={{ fontWeight: 700, marginBottom: 6 }}>What is wrong</div>
                  <div style={{ fontSize: 13, lineHeight: 1.5 }}>
                    {selected.reuseCount >= 2 ? (
                      <div style={{ marginBottom: 6 }}>
                        Why: Password reused across {selected.reuseCount} accounts.
                      </div>
                    ) : null}

                    {selected.weakReasons.length ? (
                      <div>Why: {selected.weakReasons.join(", ")}</div>
                    ) : (
                      <div style={{ opacity: 0.75 }}>
                        No weakness signals for the current policy.
                      </div>
                    )}
                  </div>
                </div>

                <div style={{ marginTop: 14 }}>
                  <div style={{ fontWeight: 700, marginBottom: 6 }}>What to fix</div>
                  <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: 1.5 }}>
                    {selectedFixes.map((f, idx) => (
                      <li key={idx} style={{ marginBottom: 6 }}>
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>

                <div style={{ marginTop: 14 }}>
                  <div style={{ fontWeight: 700, marginBottom: 6 }}>Notes</div>
                  <div style={{ opacity: 0.75, fontSize: 12, lineHeight: 1.5 }}>
                    This tool does not reveal passwords. It highlights reuse and weakness signals so you
                    can prioritize password changes and enable MFA on important accounts.
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
