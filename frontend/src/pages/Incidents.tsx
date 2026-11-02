import { useState, useEffect, useMemo, useCallback } from 'react';
import api from '../services/api';
import {
  ShieldAlert,
  Download,
  CheckCircle,
  Clock,
  RotateCcw,
  Search,
  AlertTriangle,
  FolderLock,
} from 'lucide-react';

const SEVERITY_STYLES: Record<string, { badge: string; border: string }> = {
  CRITICAL: {
    badge: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30',
    border: 'border-l-rose-500',
  },
  HIGH: {
    badge: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30',
    border: 'border-l-orange-500',
  },
  MEDIUM: {
    badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
    border: 'border-l-amber-500',
  },
  LOW: {
    badge: 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30',
    border: 'border-l-sky-500',
  },
};

const Incidents = () => {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/incidents/');
      setIncidents(res.data);
    } catch (e) {
      console.error('Failed to load incidents', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const handleDownloadPdf = async (incidentId: number, incidentNumber: string) => {
    setDownloadingId(incidentId);
    try {
      const response = await api.get(`/reports/incident/${incidentId}/pdf`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `incident_${incidentNumber}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (e) {
      console.error('Failed to download PDF:', e);
      alert('Failed to generate incident PDF report.');
    } finally {
      setDownloadingId(null);
    }
  };

  const stats = useMemo(() => {
    let openCount = 0;
    let critCount = 0;
    let resolvedCount = 0;
    incidents.forEach(inc => {
      if (inc.status === 'RESOLVED' || inc.status === 'CLOSED') resolvedCount++;
      else openCount++;
      if (inc.severity === 'CRITICAL') critCount++;
    });
    return { total: incidents.length, openCount, critCount, resolvedCount };
  }, [incidents]);

  const filteredIncidents = useMemo(() => {
    return incidents.filter(inc => {
      if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const num = (inc.incident_number || '').toLowerCase();
        const title = (inc.title || '').toLowerCase();
        const desc = (inc.description || '').toLowerCase();
        return num.includes(q) || title.includes(q) || desc.includes(q);
      }
      return true;
    });
  }, [incidents, statusFilter, searchQuery]);

  return (
    <div className="space-y-6">
      {/* ─── Top Stats Grid ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">
              Total Incidents
            </span>
            <h3 className="text-2xl font-bold font-mono text-slate-900 dark:text-white mt-0.5">
              {stats.total}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-600 dark:text-blue-400">
            <FolderLock className="w-5 h-5" />
          </div>
        </div>

        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-rose-500 uppercase font-semibold">
              Critical Severity
            </span>
            <h3 className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-0.5">
              {stats.critCount}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-500">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-amber-500 uppercase font-semibold">
              Active / Open Cases
            </span>
            <h3 className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-0.5">
              {stats.openCount}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-500">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="card-3d p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-emerald-500 uppercase font-semibold">
              Resolved / Closed
            </span>
            <h3 className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-0.5">
              {stats.resolvedCount}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500">
            <CheckCircle className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* ─── Filter & Control Bar ────────────────────────────────────────────────── */}
      <div className="card-3d p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex flex-1 items-center flex-wrap gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter by Incident #, title, or details..."
              className="input-3d w-full pl-9 pr-3 py-1.5 text-xs font-mono"
            />
          </div>

          <div className="flex items-center space-x-1.5">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Status:</span>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="input-3d px-2.5 py-1.5 text-xs font-mono cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">NEW</option>
              <option value="TRIAGED">TRIAGED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <span className="text-[11px] font-mono text-slate-400">
            Cases: <strong className="text-slate-700 dark:text-slate-200">{filteredIncidents.length}</strong>
          </span>
          <button
            onClick={fetchIncidents}
            disabled={loading}
            className="btn-3d-secondary px-3.5 py-1.5 rounded-lg text-xs flex items-center gap-1.5 font-medium"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ─── Incident Cards Stream ───────────────────────────────────────────────── */}
      {loading ? (
        <div className="card-3d p-12 text-center text-slate-400">
          <div className="flex flex-col items-center justify-center space-y-2">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-xs font-mono">Loading incident repository...</span>
          </div>
        </div>
      ) : filteredIncidents.length === 0 ? (
        <div className="card-3d p-12 text-center text-slate-500 dark:text-slate-400">
          <FolderLock className="w-12 h-12 mx-auto mb-3 text-slate-300 dark:text-slate-600" />
          <h4 className="font-bold text-base text-slate-800 dark:text-slate-200">No Incidents Escalated</h4>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Escalate a security threat from the Threat Alerts page to create a formal case file.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredIncidents.map(inc => {
            const sev = SEVERITY_STYLES[inc.severity] || SEVERITY_STYLES.HIGH;
            const isDownloading = downloadingId === inc.id;

            return (
              <div
                key={inc.id}
                className={`card-3d-interactive border-l-4 ${sev.border} p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4`}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-3 mb-2 flex-wrap gap-y-1">
                    <ShieldAlert className="w-4 h-4 text-slate-400 shrink-0" />
                    <span className="font-mono font-bold text-sm text-blue-600 dark:text-blue-400">
                      {inc.incident_number}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sev.badge}`}>
                      {inc.severity}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        inc.status === 'RESOLVED' || inc.status === 'CLOSED'
                          ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                          : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30'
                      }`}
                    >
                      {inc.status}
                    </span>
                  </div>

                  <h3 className="font-bold text-base text-slate-900 dark:text-white truncate">
                    {inc.title}
                  </h3>

                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-3xl leading-relaxed">
                    {inc.description || 'No detailed incident description provided.'}
                  </p>

                  <div className="text-[11px] text-slate-400 font-mono mt-3 flex items-center space-x-4">
                    <span className="flex items-center">
                      <Clock className="w-3 h-3 mr-1 text-slate-400" />
                      Opened: {new Date(inc.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Right Actions */}
                <div className="shrink-0 flex items-center space-x-2">
                  <button
                    onClick={() => handleDownloadPdf(inc.id, inc.incident_number)}
                    disabled={isDownloading}
                    className="btn-3d-secondary px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2"
                  >
                    <Download className={`w-3.5 h-3.5 text-blue-500 ${isDownloading ? 'animate-bounce' : ''}`} />
                    <span>{isDownloading ? 'Generating PDF...' : 'Download PDF Report'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default Incidents;
