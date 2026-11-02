import { useState, useEffect, useMemo, useCallback } from 'react';
import api from '../services/api';
import {
  FileText,
  Search,
  RotateCcw,
  ShieldAlert,
  AlertTriangle,
  Info,
  Copy,
  X,
  ChevronRight,
  Database,
} from 'lucide-react';

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: {
    bg: 'bg-rose-500/10 dark:bg-rose-500/20',
    text: 'text-rose-600 dark:text-rose-400',
    border: 'border-rose-500/30',
  },
  HIGH: {
    bg: 'bg-orange-500/10 dark:bg-orange-500/20',
    text: 'text-orange-600 dark:text-orange-400',
    border: 'border-orange-500/30',
  },
  ERROR: {
    bg: 'bg-rose-500/10 dark:bg-rose-500/20',
    text: 'text-rose-600 dark:text-rose-400',
    border: 'border-rose-500/30',
  },
  WARNING: {
    bg: 'bg-amber-500/10 dark:bg-amber-500/20',
    text: 'text-amber-600 dark:text-amber-400',
    border: 'border-amber-500/30',
  },
  MEDIUM: {
    bg: 'bg-amber-500/10 dark:bg-amber-500/20',
    text: 'text-amber-600 dark:text-amber-400',
    border: 'border-amber-500/30',
  },
  LOW: {
    bg: 'bg-sky-500/10 dark:bg-sky-500/20',
    text: 'text-sky-600 dark:text-sky-400',
    border: 'border-sky-500/30',
  },
  INFO: {
    bg: 'bg-blue-500/10 dark:bg-blue-500/20',
    text: 'text-blue-600 dark:text-blue-400',
    border: 'border-blue-500/30',
  },
};

const Logs = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState<any | null>(null);
  const [copied, setCopied] = useState(false);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get('/logs/?limit=100');
      setLogs(response.data);
    } catch (error) {
      console.error('Failed to fetch logs', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Distinct event types
  const uniqueTypes = useMemo(() => {
    const types = new Set<string>();
    logs.forEach(l => {
      if (l.event_type) types.add(l.event_type);
    });
    return Array.from(types).sort();
  }, [logs]);

  // Filtered logs
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      if (severityFilter !== 'ALL' && (log.severity || 'INFO') !== severityFilter) {
        return false;
      }
      if (typeFilter !== 'ALL' && log.event_type !== typeFilter) {
        return false;
      }
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const msg = (log.message || '').toLowerCase();
        const ip = (log.source_ip || '').toLowerCase();
        const user = (log.username || '').toLowerCase();
        const evType = (log.event_type || '').toLowerCase();
        return msg.includes(query) || ip.includes(query) || user.includes(query) || evType.includes(query);
      }
      return true;
    });
  }, [logs, severityFilter, typeFilter, searchTerm]);

  // Statistics
  const stats = useMemo(() => {
    let critical = 0;
    let warning = 0;
    let info = 0;
    logs.forEach(l => {
      const s = l.severity || 'INFO';
      if (s === 'CRITICAL' || s === 'HIGH' || s === 'ERROR') critical++;
      else if (s === 'WARNING' || s === 'MEDIUM') warning++;
      else info++;
    });
    return { total: logs.length, critical, warning, info };
  }, [logs]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* ─── Top Stats Bar ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">
              Total Ingested
            </span>
            <h3 className="text-2xl font-bold font-mono text-slate-900 dark:text-white mt-0.5">
              {stats.total}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-600 dark:text-blue-400">
            <Database className="w-5 h-5" />
          </div>
        </div>

        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-rose-500 uppercase font-semibold">
              Critical / High
            </span>
            <h3 className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-0.5">
              {stats.critical}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-500">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-amber-500 uppercase font-semibold">
              Warnings
            </span>
            <h3 className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-0.5">
              {stats.warning}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-500">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">
              Normal / Info
            </span>
            <h3 className="text-2xl font-bold font-mono text-slate-700 dark:text-slate-200 mt-0.5">
              {stats.info}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-slate-500/10 border border-slate-500/20 flex items-center justify-center text-slate-500">
            <Info className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* ─── Main Explorer Panel ────────────────────────────────────────────────── */}
      <div className="card-3d overflow-hidden">
        {/* Filter & Control Bar */}
        <div className="p-4 sm:p-5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0c121e]/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex flex-1 items-center flex-wrap gap-3">
            {/* Search Box */}
            <div className="relative flex-1 min-w-[220px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search raw log message, IP, user, type..."
                className="input-3d w-full pl-9 pr-3 py-1.5 text-xs font-mono"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Severity Filter */}
            <div className="flex items-center space-x-1.5">
              <span className="text-[11px] font-mono text-slate-400 uppercase">Sev:</span>
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="input-3d px-2.5 py-1.5 text-xs font-mono cursor-pointer"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="WARNING">WARNING</option>
                <option value="INFO">INFO</option>
              </select>
            </div>

            {/* Type Filter */}
            <div className="flex items-center space-x-1.5">
              <span className="text-[11px] font-mono text-slate-400 uppercase">Type:</span>
              <select
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value)}
                className="input-3d px-2.5 py-1.5 text-xs font-mono cursor-pointer"
              >
                <option value="ALL">All Event Types</option>
                {uniqueTypes.map(t => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            {(searchTerm || severityFilter !== 'ALL' || typeFilter !== 'ALL') && (
              <button
                onClick={() => {
                  setSearchTerm('');
                  setSeverityFilter('ALL');
                  setTypeFilter('ALL');
                }}
                className="text-xs text-blue-600 dark:text-blue-400 hover:underline px-2 py-1"
              >
                Reset
              </button>
            )}
          </div>

          {/* Refresh Action */}
          <div className="flex items-center space-x-3 shrink-0">
            <span className="text-[11px] font-mono text-slate-400">
              Showing <span className="font-bold text-slate-700 dark:text-slate-200">{filteredLogs.length}</span> of {logs.length}
            </span>
            <button
              onClick={fetchLogs}
              disabled={loading}
              className="btn-3d-secondary px-3.5 py-1.5 rounded-lg text-xs flex items-center gap-1.5 font-medium"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-100/70 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-200 dark:border-slate-800">
                <th className="px-4 py-3 font-semibold">Timestamp</th>
                <th className="px-4 py-3 font-semibold">Severity</th>
                <th className="px-4 py-3 font-semibold">Source IP</th>
                <th className="px-4 py-3 font-semibold">User</th>
                <th className="px-4 py-3 font-semibold">Event Type</th>
                <th className="px-4 py-3 font-semibold">Normalized Message</th>
                <th className="px-4 py-3 font-semibold">Status</th>
                <th className="px-4 py-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Querying normalized log events...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-slate-400">
                    <p className="font-sans text-sm">No matching log events found.</p>
                    <p className="text-[11px] font-mono text-slate-500 mt-1">Try relaxing your search terms or filters.</p>
                  </td>
                </tr>
              ) : (
                filteredLogs.map(log => {
                  const badge = SEVERITY_BADGES[log.severity || 'INFO'] || SEVERITY_BADGES.INFO;
                  const isSelected = selectedLog?.id === log.id;
                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      className={`cursor-pointer transition-colors duration-150 ${
                        isSelected
                          ? 'bg-blue-50/80 dark:bg-blue-900/20'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="px-4 py-3 whitespace-nowrap text-slate-500 dark:text-slate-400">
                        {new Date(log.event_time).toLocaleTimeString()}
                        <span className="text-[10px] text-slate-400 dark:text-slate-600 block">
                          {new Date(log.event_time).toLocaleDateString()}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badge.bg} ${badge.text} ${badge.border}`}
                        >
                          {log.severity || 'INFO'}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-700 dark:text-slate-300 font-semibold">
                        {log.source_ip || '—'}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-600 dark:text-slate-400">
                        {log.username || '—'}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-[10px]">
                          {log.event_type || 'GENERAL'}
                        </span>
                      </td>
                      <td className="px-4 py-3 max-w-md truncate font-sans text-slate-800 dark:text-slate-200" title={log.message}>
                        {log.message}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            log.parse_status === 'PARSED' || log.parse_status === 'SUCCESS'
                              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                              : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                          }`}
                        >
                          {log.parse_status || 'PARSED'}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-right">
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            setSelectedLog(log);
                          }}
                          className="p-1 rounded text-slate-400 hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition"
                          title="Inspect Event"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ─── 3D Slide-Over / Inspection Modal ───────────────────────────────────── */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-in fade-in duration-200">
          <div className="card-3d-elevated w-full max-w-2xl bg-white dark:bg-[#0f172a] overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-[#0c121e]">
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-600 dark:text-blue-400">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    Event #{selectedLog.id}
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        SEVERITY_BADGES[selectedLog.severity || 'INFO']?.bg || ''
                      } ${SEVERITY_BADGES[selectedLog.severity || 'INFO']?.text || ''} ${
                        SEVERITY_BADGES[selectedLog.severity || 'INFO']?.border || ''
                      }`}
                    >
                      {selectedLog.severity || 'INFO'}
                    </span>
                  </h3>
                  <span className="text-[11px] font-mono text-slate-400">
                    Captured: {new Date(selectedLog.event_time).toLocaleString()}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
              {/* Key Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-[#0a0f1a] border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Source IP</span>
                  <span className="text-xs font-mono font-bold text-slate-900 dark:text-white mt-0.5 block truncate">
                    {selectedLog.source_ip || 'N/A'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-[#0a0f1a] border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Username</span>
                  <span className="text-xs font-mono font-bold text-slate-900 dark:text-white mt-0.5 block truncate">
                    {selectedLog.username || 'N/A'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-[#0a0f1a] border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Event Type</span>
                  <span className="text-xs font-mono font-bold text-blue-600 dark:text-blue-400 mt-0.5 block truncate">
                    {selectedLog.event_type || 'GENERAL'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-[#0a0f1a] border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Parse Status</span>
                  <span className="text-xs font-mono font-bold text-emerald-600 dark:text-emerald-400 mt-0.5 block truncate">
                    {selectedLog.parse_status || 'PARSED'}
                  </span>
                </div>
              </div>

              {/* Raw Message Block */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase">
                    Raw Message Content
                  </span>
                  <button
                    onClick={() => copyToClipboard(selectedLog.message || '')}
                    className="flex items-center space-x-1 text-xs text-blue-600 dark:text-blue-400 hover:underline font-mono"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copied ? 'Copied!' : 'Copy Payload'}</span>
                  </button>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-100 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 font-mono text-xs text-slate-800 dark:text-slate-200 break-all leading-relaxed shadow-inner">
                  {selectedLog.message}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex justify-end bg-slate-50 dark:bg-[#0c121e]">
              <button
                onClick={() => setSelectedLog(null)}
                className="btn-3d-secondary px-4 py-2 rounded-lg text-xs font-semibold"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Logs;
