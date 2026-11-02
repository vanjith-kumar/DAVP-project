import { useState, useEffect, useMemo, useCallback } from 'react';
import api from '../services/api';
import {
  ShieldAlert,
  Zap,
  Edit3,
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  Sparkles,
  ArrowUpRight,
  Clock,
  Send,
  Search,
} from 'lucide-react';

const SEVERITY_CONFIG: Record<string, { border: string; badge: string; icon: string }> = {
  CRITICAL: {
    border: 'border-l-rose-500',
    badge: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30',
    icon: 'text-rose-500',
  },
  HIGH: {
    border: 'border-l-orange-500',
    badge: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30',
    icon: 'text-orange-500',
  },
  MEDIUM: {
    border: 'border-l-amber-500',
    badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
    icon: 'text-amber-500',
  },
  LOW: {
    border: 'border-l-sky-500',
    badge: 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30',
    icon: 'text-sky-500',
  },
  INFO: {
    border: 'border-l-blue-500',
    badge: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30',
    icon: 'text-blue-500',
  },
};

const Alerts = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [explanations, setExplanations] = useState<Record<number, any>>({});
  const [explainingId, setExplainingId] = useState<number | null>(null);
  const [notes, setNotes] = useState<Record<number, any[]>>({});
  const [newNote, setNewNote] = useState<Record<number, string>>({});
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusMsg, setStatusMsg] = useState<{ id: number; text: string; type: 'success' | 'error' } | null>(null);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get('/alerts/?limit=50');
      setAlerts(response.data);
    } catch (error) {
      console.error('Failed to fetch alerts', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const fetchExplanation = async (id: number) => {
    try {
      const response = await api.get(`/ai/alerts/${id}/explanation`);
      setExplanations(prev => ({ ...prev, [id]: response.data }));
    } catch {
      // expected if no explanation exists yet
    }
  };

  const handleExplain = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    setExplainingId(id);
    try {
      await api.post(`/ai/alerts/${id}/explain`);
      await fetchExplanation(id);
      setExpandedId(id);
      setStatusMsg({ id, text: 'AI explanation successfully generated!', type: 'success' });
    } catch (error) {
      console.error('Failed to generate explanation', error);
      setStatusMsg({ id, text: 'Failed to generate AI explanation.', type: 'error' });
    } finally {
      setExplainingId(null);
      setTimeout(() => setStatusMsg(null), 4000);
    }
  };

  const fetchNotes = async (id: number) => {
    try {
      const res = await api.get(`/alerts/${id}/notes`);
      setNotes(prev => ({ ...prev, [id]: res.data }));
    } catch (error) {
      console.error(error);
    }
  };

  const handleAddNote = async (id: number) => {
    if (!newNote[id]?.trim()) return;
    try {
      await api.post(`/alerts/${id}/notes`, { note_text: newNote[id] });
      setNewNote(prev => ({ ...prev, [id]: '' }));
      fetchNotes(id);
    } catch (error) {
      console.error(error);
    }
  };

  const handleExpand = (id: number) => {
    if (expandedId === id) {
      setExpandedId(null);
    } else {
      setExpandedId(id);
      if (!explanations[id]) fetchExplanation(id);
      if (!notes[id]) fetchNotes(id);
    }
  };

  const handleAction = async (id: number, action: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.post(`/alerts/${id}/${action}`);
      fetchAlerts();
      setStatusMsg({ id, text: `Alert marked as ${action.toUpperCase()}`, type: 'success' });
    } catch (error) {
      console.error('Action failed', error);
      setStatusMsg({ id, text: `Failed to update alert to ${action}`, type: 'error' });
    } finally {
      setTimeout(() => setStatusMsg(null), 4000);
    }
  };

  const handleEscalate = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.post(`/incidents/from-alert/${id}`);
      fetchAlerts();
      setStatusMsg({ id, text: 'Incident successfully created from alert!', type: 'success' });
    } catch (err) {
      console.error(err);
      setStatusMsg({ id, text: 'Failed to escalate alert to incident.', type: 'error' });
    } finally {
      setTimeout(() => setStatusMsg(null), 4000);
    }
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const title = (a.title || '').toLowerCase();
        const ip = (a.source_ip || '').toLowerCase();
        const status = (a.status || '').toLowerCase();
        return title.includes(q) || ip.includes(q) || status.includes(q);
      }
      return true;
    });
  }, [alerts, filterSeverity, searchQuery]);

  return (
    <div className="space-y-6">
      {/* ─── Control Bar ────────────────────────────────────────────────────────── */}
      <div className="card-3d p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex flex-1 items-center flex-wrap gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search alerts by title, source IP, or status..."
              className="input-3d w-full pl-9 pr-3 py-1.5 text-xs font-mono"
            />
          </div>

          {/* Severity Filter Buttons */}
          <div className="flex items-center space-x-1 bg-slate-100 dark:bg-slate-800/80 p-1 rounded-lg border border-slate-200 dark:border-slate-700/60">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-1 text-xs font-mono rounded-md font-semibold transition ${
                  filterSeverity === sev
                    ? 'bg-white dark:bg-[#0f172a] text-blue-600 dark:text-blue-400 shadow-xs'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <span className="text-[11px] font-mono text-slate-400">
            Total Alerts: <span className="font-bold text-slate-700 dark:text-slate-200">{filteredAlerts.length}</span>
          </span>
          <button
            onClick={fetchAlerts}
            disabled={loading}
            className="btn-3d-secondary px-3.5 py-1.5 rounded-lg text-xs flex items-center gap-1.5 font-medium"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ─── Alerts Stream ──────────────────────────────────────────────────────── */}
      {loading ? (
        <div className="card-3d p-12 text-center text-slate-400">
          <div className="flex flex-col items-center justify-center space-y-2">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-xs font-mono">Loading threat detections...</span>
          </div>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="card-3d p-12 text-center text-slate-500 dark:text-slate-400">
          <ShieldAlert className="w-12 h-12 mx-auto mb-3 text-slate-300 dark:text-slate-600" />
          <h4 className="font-bold text-base text-slate-800 dark:text-slate-200">No Security Detections</h4>
          <p className="text-xs text-slate-400 font-mono mt-1">All monitored systems are within normal operational baselines.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredAlerts.map(alertItem => {
            const conf = SEVERITY_CONFIG[alertItem.severity] || SEVERITY_CONFIG.MEDIUM;
            const isExpanded = expandedId === alertItem.id;
            const isExplaining = explainingId === alertItem.id;
            const itemMsg = statusMsg?.id === alertItem.id ? statusMsg : null;

            return (
              <div
                key={alertItem.id}
                className={`card-3d border-l-4 ${conf.border} overflow-hidden transition-all duration-200`}
              >
                {/* Status Message Notification Bar */}
                {itemMsg && (
                  <div
                    className={`px-4 py-1.5 text-xs font-mono flex items-center justify-between ${
                      itemMsg.type === 'success'
                        ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-b border-emerald-500/20'
                        : 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-b border-rose-500/20'
                    }`}
                  >
                    <span>{itemMsg.text}</span>
                    <button onClick={() => setStatusMsg(null)} className="text-[10px] font-bold">×</button>
                  </div>
                )}

                {/* Main Card Header */}
                <div
                  onClick={() => handleExpand(alertItem.id)}
                  className="p-5 flex flex-col lg:flex-row justify-between items-start lg:items-center cursor-pointer hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition gap-4"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3 mb-2 flex-wrap gap-y-1">
                      <Zap className={`w-4 h-4 ${conf.icon} shrink-0`} />
                      <h3 className="font-bold text-sm sm:text-base text-slate-900 dark:text-white truncate">
                        {alertItem.title}
                      </h3>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${conf.badge}`}>
                        {alertItem.severity}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          alertItem.status === 'NEW'
                            ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                            : alertItem.status === 'INVESTIGATING'
                            ? 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30'
                            : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {alertItem.status}
                      </span>
                    </div>

                    <div className="text-xs text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono">
                      <span className="flex items-center">
                        <Activity className="w-3 h-3 mr-1 text-slate-400" />
                        Source IP: <strong className="ml-1 text-slate-700 dark:text-slate-300">{alertItem.source_ip || 'N/A'}</strong>
                      </span>
                      <span>•</span>
                      <span>Events: <strong className="text-slate-700 dark:text-slate-300">{alertItem.event_count || 1}</strong></span>
                      <span>•</span>
                      <span className="flex items-center">
                        <AlertTriangle className="w-3 h-3 mr-1 text-amber-500" />
                        Risk: <strong className="ml-1 text-amber-600 dark:text-amber-400">{alertItem.risk_score || 75}/100</strong>
                      </span>
                      <span>•</span>
                      <span className="flex items-center">
                        <Clock className="w-3 h-3 mr-1 text-slate-400" />
                        {new Date(alertItem.last_seen_at || alertItem.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  {/* Actions Cluster */}
                  <div className="flex items-center space-x-2 shrink-0 flex-wrap gap-y-2">
                    {alertItem.status !== 'RESOLVED' && alertItem.status !== 'FALSE_POSITIVE' && (
                      <>
                        {/* AI Explain Button */}
                        <button
                          onClick={e => handleExplain(alertItem.id, e)}
                          disabled={isExplaining}
                          className="btn-3d px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-purple-600 to-indigo-600 text-white flex items-center gap-1.5 shadow-sm hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50"
                        >
                          <Sparkles className={`w-3.5 h-3.5 ${isExplaining ? 'animate-spin' : ''}`} />
                          <span>{isExplaining ? 'Analyzing...' : 'AI Explain'}</span>
                        </button>

                        {/* Escalate to Incident */}
                        <button
                          onClick={e => handleEscalate(alertItem.id, e)}
                          className="btn-3d-danger px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1"
                        >
                          <ArrowUpRight className="w-3.5 h-3.5" />
                          <span>Escalate</span>
                        </button>

                        {/* Status update buttons */}
                        <button
                          onClick={e => handleAction(alertItem.id, 'investigating', e)}
                          className="btn-3d-secondary px-3 py-1.5 rounded-lg text-xs"
                        >
                          Investigate
                        </button>
                        <button
                          onClick={e => handleAction(alertItem.id, 'resolve', e)}
                          className="btn-3d px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white"
                        >
                          Resolve
                        </button>
                      </>
                    )}

                    <div className="p-1 text-slate-400">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                </div>

                {/* ─── Expanded Investigation Workspace ───────────────────────────── */}
                {isExpanded && (
                  <div className="border-t border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#0c121e]/80 p-5 grid grid-cols-1 lg:grid-cols-3 gap-5 animate-in slide-in-from-top-2 duration-200">
                    {/* Left: AI & Threat Intel */}
                    <div className="lg:col-span-2 space-y-4">
                      {/* AI Intelligence Card */}
                      <div className="card-3d p-4 bg-white dark:bg-[#0f172a] border border-purple-500/20">
                        <div className="flex items-center space-x-2 border-b border-slate-100 dark:border-slate-800 pb-2.5 mb-3">
                          <Sparkles className="w-4 h-4 text-purple-500" />
                          <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                            AI-Assisted Security Telemetry Analysis
                          </h4>
                        </div>

                        {explanations[alertItem.id]?.explanation ? (
                          <div className="space-y-3.5 text-xs">
                            <div>
                              <span className="font-semibold text-slate-700 dark:text-slate-300 block mb-1">
                                Executive Summary:
                              </span>
                              <p className="p-3 rounded-lg bg-slate-50 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 font-sans leading-relaxed">
                                {explanations[alertItem.id].explanation.summary}
                              </p>
                            </div>

                            <div className="flex items-center space-x-2">
                              <span className="font-semibold text-slate-700 dark:text-slate-300 font-mono">
                                Potential Attack Vector:
                              </span>
                              <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-600 dark:text-purple-400 font-mono font-bold border border-purple-500/20">
                                {explanations[alertItem.id].explanation.possible_attack_type || 'Unknown Vector'}
                              </span>
                            </div>

                            {explanations[alertItem.id].explanation.investigation_steps && (
                              <div>
                                <span className="font-semibold text-slate-700 dark:text-slate-300 block mb-1.5 font-mono">
                                  Prescribed Response Playbook:
                                </span>
                                <ul className="space-y-1.5">
                                  {explanations[alertItem.id].explanation.investigation_steps.map((st: string, idx: number) => (
                                    <li
                                      key={idx}
                                      className="p-2 rounded bg-slate-50 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 flex items-start space-x-2 text-xs"
                                    >
                                      <span className="text-blue-500 font-bold font-mono">0{idx + 1}.</span>
                                      <span>{st}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="py-6 text-center text-xs text-slate-400 font-mono">
                            <p>No AI analysis on record.</p>
                            <p className="text-[11px] text-slate-500 mt-1">Click the "AI Explain" button above to evaluate this alert with Deep Learning models.</p>
                          </div>
                        )}
                      </div>

                      {/* Threat Intel Card */}
                      <div className="card-3d p-4 bg-white dark:bg-[#0f172a]">
                        <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider mb-2">
                          Threat Intelligence Indicator
                        </h4>
                        <p className="text-xs font-mono text-slate-600 dark:text-slate-400">
                          Target Identity:{' '}
                          <span className="font-bold text-blue-600 dark:text-blue-400">
                            {alertItem.source_ip || 'Internal Asset'}
                          </span>
                        </p>
                      </div>
                    </div>

                    {/* Right: Analyst Investigation Notes */}
                    <div className="card-3d p-4 bg-white dark:bg-[#0f172a] flex flex-col h-full min-h-[320px]">
                      <div className="flex items-center space-x-2 border-b border-slate-100 dark:border-slate-800 pb-2.5 mb-3">
                        <Edit3 className="w-4 h-4 text-blue-500" />
                        <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                          Analyst Notes & Audit Log
                        </h4>
                      </div>

                      <div className="flex-1 overflow-y-auto space-y-2 mb-3 max-h-56 pr-1 text-xs">
                        {notes[alertItem.id]?.map(n => (
                          <div
                            key={n.id}
                            className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-slate-800 dark:text-slate-200"
                          >
                            <p className="leading-relaxed">{n.note_text}</p>
                            <span className="text-[10px] text-slate-400 font-mono block mt-1">
                              {new Date(n.created_at).toLocaleString()}
                            </span>
                          </div>
                        ))}
                        {(!notes[alertItem.id] || notes[alertItem.id].length === 0) && (
                          <div className="text-slate-400 text-center py-8 text-xs font-mono">
                            No analyst annotations yet.
                          </div>
                        )}
                      </div>

                      {/* Add Note Input */}
                      <div className="mt-auto space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                        <textarea
                          rows={2}
                          value={newNote[alertItem.id] || ''}
                          onChange={e => setNewNote(prev => ({ ...prev, [alertItem.id]: e.target.value }))}
                          placeholder="Log an investigative observation..."
                          className="input-3d w-full p-2 text-xs resize-none font-mono"
                        />
                        <button
                          onClick={() => handleAddNote(alertItem.id)}
                          className="btn-3d-primary w-full py-1.5 rounded-lg text-xs flex items-center justify-center gap-1.5 font-semibold"
                        >
                          <Send className="w-3 h-3" />
                          <span>Commit Note</span>
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default Alerts;
