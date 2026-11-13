import React, { useEffect, useState } from "react";
import { X, Database, Plus, Trash2, RefreshCw, Check, AlertCircle } from "lucide-react";
import { DkimDnsRecord } from "../types";
import { deleteDkimRecord, fetchDkimCache, importDkimSnapshot } from "../services/api";

interface DkimCacheModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DkimCacheModal: React.FC<DkimCacheModalProps> = ({ isOpen, onClose }) => {
  const [records, setRecords] = useState<DkimDnsRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Import form state
  const [snapshotName, setSnapshotName] = useState("corporate_zone_2026.json");
  const [domain, setDomain] = useState("");
  const [selector, setSelector] = useState("");
  const [publicKeyTxt, setPublicKeyTxt] = useState("");
  const [notes, setNotes] = useState("");
  const [importing, setImporting] = useState(false);

  const loadCache = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchDkimCache();
      setRecords(data.items);
    } catch (err: any) {
      setError(err.message || "Failed to load DKIM DNS cache.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadCache();
    }
  }, [isOpen]);

  const handleImportSingle = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || !selector.trim() || !publicKeyTxt.trim()) return;

    setImporting(true);
    setError(null);
    setSuccessMsg(null);

    try {
      await importDkimSnapshot({
        source_snapshot: snapshotName.trim() || "manual_entry",
        records: [
          {
            domain: domain.trim(),
            selector: selector.trim(),
            public_key_txt: publicKeyTxt.trim(),
            notes: notes.trim(),
          },
        ],
      });
      setSuccessMsg(`Imported DKIM key for ${selector.trim()}._domainkey.${domain.trim()}`);
      setDomain("");
      setSelector("");
      setPublicKeyTxt("");
      setNotes("");
      await loadCache();
    } catch (err: any) {
      setError(err.message || "Import failed.");
    } finally {
      setImporting(false);
    }
  };

  const handleDelete = async (id: string, dom: string, sel: string) => {
    if (!confirm(`Delete cached DKIM record for ${sel}._domainkey.${dom}?`)) return;
    try {
      await deleteDkimRecord(id);
      await loadCache();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 p-5 bg-slate-950/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                Air-Gapped DKIM DNS Cache Snapshots
              </h2>
              <p className="text-xs text-slate-400 font-sans">
                Manage local DNS TXT records used for offline cryptographic RSA-SHA256 signature verification.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadCache}
              disabled={loading}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition"
              title="Refresh cache"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 font-mono text-xs">
          {error && (
            <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-rose-300 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/40 p-3 text-emerald-300 flex items-center gap-2">
              <Check className="h-4 w-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Quick Import Form */}
          <form onSubmit={handleImportSingle} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5 text-xs">
                <Plus className="h-3.5 w-3.5 text-emerald-400" /> Import DNS TXT Key Snapshot
              </span>
              <span className="text-[11px] text-slate-500">Zero network queries initiated</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Domain</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. paypal.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 placeholder-slate-600 focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Selector</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. s1 or 202601"
                  value={selector}
                  onChange={(e) => setSelector(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 placeholder-slate-600 focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Source Snapshot Identifier</label>
                <input
                  type="text"
                  placeholder="e.g. corporate_dns_zone.json"
                  value={snapshotName}
                  onChange={(e) => setSnapshotName(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 placeholder-slate-600 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                DNS TXT Record Content (v=DKIM1; k=rsa; p=...)
              </label>
              <textarea
                required
                rows={2}
                placeholder="v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ..."
                value={publicKeyTxt}
                onChange={(e) => setPublicKeyTxt(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-[11px] text-slate-200 placeholder-slate-600 focus:border-emerald-500 focus:outline-none font-mono"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={importing || !domain.trim() || !selector.trim() || !publicKeyTxt.trim()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 transition disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                {importing ? "Importing..." : "Add to Offline Cache"}
              </button>
            </div>
          </form>

          {/* Cached Records Table */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-300 uppercase tracking-wider text-xs">
                Cached DNS Key Records ({records.length})
              </span>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-3">Domain</th>
                    <th className="p-3">Selector</th>
                    <th className="p-3">Source Snapshot</th>
                    <th className="p-3">Public Key (Truncated)</th>
                    <th className="p-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
                  {records.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-slate-500">
                        No DKIM DNS records cached. Import a zone snapshot to enable offline cryptographic verification.
                      </td>
                    </tr>
                  ) : (
                    records.map((r) => (
                      <tr key={r.id} className="hover:bg-slate-800/40">
                        <td className="p-3 font-bold text-white">{r.domain}</td>
                        <td className="p-3 text-cyan-400">{r.selector}</td>
                        <td className="p-3 text-slate-400">{r.source_snapshot}</td>
                        <td className="p-3 text-slate-500 max-w-xs truncate" title={r.public_key_txt}>
                          {r.public_key_txt.substring(0, 45)}...
                        </td>
                        <td className="p-3 text-right">
                          <button
                            type="button"
                            onClick={() => handleDelete(r.id, r.domain, r.selector)}
                            className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-950/50 transition"
                            title="Delete cached record"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-slate-800 p-4 bg-slate-950/50 flex justify-between items-center text-xs text-slate-500 font-mono">
          <span>Air-Gapped: All cryptographic checks resolve against this local SQLite store.</span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-1.5 text-xs text-slate-300 hover:bg-slate-700 hover:text-white transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
