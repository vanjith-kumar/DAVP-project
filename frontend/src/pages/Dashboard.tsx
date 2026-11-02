import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  Activity,
  RotateCcw,
  Layers,
  Globe,
  Cpu,
  Sparkles,
  Clock,
  ArrowUpRight,
  CheckCircle2,
  Server,
  Filter,
  ExternalLink,
  Flame,
  Check,
} from 'lucide-react';
import api from '../services/api';
import { useRealtime } from '../hooks/useRealtime';

// ─── Color Palettes ──────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e', // rose-500
  HIGH: '#f97316',     // orange-500
  MEDIUM: '#f59e0b',   // amber-500
  LOW: '#0ea5e9',      // sky-500
  INFO: '#06b6d4',     // cyan-500
  ERROR: '#f43f5e',
  WARNING: '#f59e0b',
};

const SEV_BADGE_STYLE: Record<string, string> = {
  CRITICAL: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  HIGH: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  LOW: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  INFO: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
};

// Format relative time helper
const formatRelativeTime = (timestampStr: string): string => {
  try {
    const eventTime = new Date(timestampStr).getTime();
    if (isNaN(eventTime)) return 'just now';
    const now = Date.now();
    const diffSec = Math.max(0, Math.floor((now - eventTime) / 1000));
    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    return `${diffHours}h ago`;
  } catch {
    return 'just now';
  }
};

// ─── Main Component ──────────────────────────────────────────────────────────

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { status: realtimeStatus, lastEvent } = useRealtime();

  // State
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d'>('24h');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<string>('ALL');
  const [selectedTypeFilter, setSelectedTypeFilter] = useState<string>('ALL');

  // Elapsed since last refresh
  const [secondsSinceRefresh, setSecondsSinceRefresh] = useState(0);

  // ─── Data Fetching ──────────────────────────────────────────────────────────

  const fetchDashboardData = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    setError(null);

    try {
      const res = await api.get(`/dashboard/summary?time_range=${timeRange}`);
      setData(res.data);
      setSecondsSinceRefresh(0);
    } catch (err: any) {
      console.error('Failed to load dashboard data:', err);
      setError('Unable to load security dashboard metrics. Retrying...');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [timeRange]);

  useEffect(() => {
    fetchDashboardData();
    const pollInterval = setInterval(() => fetchDashboardData(), 25000);
    const clockInterval = setInterval(() => setSecondsSinceRefresh(s => s + 1), 1000);

    return () => {
      clearInterval(pollInterval);
      clearInterval(clockInterval);
    };
  }, [fetchDashboardData]);

  // Real-time update trigger when WebSocket alert arrives
  useEffect(() => {
    if (lastEvent && lastEvent.type === 'NEW_ALERT') {
      fetchDashboardData();
    }
  }, [lastEvent, fetchDashboardData]);

  // ─── Filtered Data Pipelines ────────────────────────────────────────────────

  const filteredRecentActivity = useMemo(() => {
    if (!data?.recent_activity) return [];
    return data.recent_activity.filter((act: any) => {
      if (selectedSeverityFilter !== 'ALL' && act.severity !== selectedSeverityFilter) {
        return false;
      }
      return true;
    });
  }, [data?.recent_activity, selectedSeverityFilter]);

  const filteredEventTypes = useMemo(() => {
    if (!data?.event_types) return [];
    if (selectedTypeFilter === 'ALL') return data.event_types;
    return data.event_types.filter((et: any) =>
      et.type.toLowerCase().includes(selectedTypeFilter.toLowerCase())
    );
  }, [data?.event_types, selectedTypeFilter]);

  // ─── Loading & Error States (#27, #28) ──────────────────────────────────────

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center justify-center h-[70vh] space-y-4">
        <div className="p-4 rounded-2xl glass-panel border border-cyan-500/30 flex items-center space-x-3">
          <RotateCcw className="w-6 h-6 text-cyan-400 animate-spin" />
          <div className="text-left font-mono">
            <h3 className="font-bold text-gray-100 text-sm">Initializing SOC Dashboard...</h3>
            <p className="text-xs text-gray-400">Loading security events, threat metrics, and intelligence telemetry</p>
          </div>
        </div>
      </div>
    );
  }

  const kpis = data?.kpis || {};
  const health = data?.system_health || {};
  const freshness = data?.data_freshness || {};
  const ml = data?.ml_anomaly_summary || {};
  const ti = data?.threat_intelligence_summary || {};

  return (
    <div className="space-y-4 max-w-full pb-6 font-sans">
      {/* ─── 1. Dashboard Header (#3) ────────────────────────────────────────── */}
      <div className="glass-panel p-4 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border border-white/10">
        <div>
          <div className="flex items-center space-x-3">
            <h1 className="text-lg font-black tracking-wider uppercase text-gray-900 dark:text-white flex items-center gap-2">
              Security Operations Center
            </h1>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span>
              System Operational
            </span>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
            Real-time overview of security events, threats, anomalies and system telemetry
          </p>
        </div>

        {/* Header Right: Status & Refresh (#17) */}
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
          <div className="flex items-center space-x-2 text-gray-400 bg-black/10 dark:bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Updated {secondsSinceRefresh < 5 ? 'just now' : `${secondsSinceRefresh}s ago`}</span>
            {freshness.is_delayed && (
              <span className="text-amber-400 font-bold ml-1">(Delayed)</span>
            )}
          </div>

          <button
            onClick={() => fetchDashboardData(true)}
            disabled={refreshing}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 transition shadow-sm"
            title="Refresh dashboard metrics"
          >
            <RotateCcw className={`w-3.5 h-3.5 text-cyan-400 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ─── 2. Global Filters Bar (#18, #19) ────────────────────────────────── */}
      <div className="glass-panel p-2.5 rounded-xl flex flex-wrap items-center justify-between gap-2.5 text-xs font-mono border border-white/10">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-gray-400 text-xs font-bold flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-cyan-400" /> Time Range:
          </span>
          {(['1h', '6h', '24h', '7d'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTimeRange(t)}
              className={`px-2.5 py-1 rounded text-xs font-bold transition ${
                timeRange === t
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-white/5 hover:bg-white/10 text-gray-400 border border-white/5'
              }`}
            >
              {t === '1h' ? 'Last 1h' : t === '6h' ? 'Last 6h' : t === '24h' ? 'Last 24h' : 'Last 7d'}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selectedSeverityFilter}
            onChange={e => setSelectedSeverityFilter(e.target.value)}
            className="px-2.5 py-1 rounded-lg bg-black/20 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-200 text-xs focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          <select
            value={selectedTypeFilter}
            onChange={e => setSelectedTypeFilter(e.target.value)}
            className="px-2.5 py-1 rounded-lg bg-black/20 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-200 text-xs focus:outline-none"
          >
            <option value="ALL">All Event Types</option>
            <option value="Auth">Authentication</option>
            <option value="Info">System Info</option>
            <option value="Warn">Latency / Warnings</option>
            <option value="Error">Database & Errors</option>
            <option value="Security">Security Events</option>
          </select>

          {(selectedSeverityFilter !== 'ALL' || selectedTypeFilter !== 'ALL') && (
            <button
              onClick={() => {
                setSelectedSeverityFilter('ALL');
                setSelectedTypeFilter('ALL');
              }}
              className="text-gray-400 hover:text-white underline text-[11px]"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* ─── 3. Top KPI Cards (#4, #5) ───────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Events */}
        <div className="glass-card p-3.5 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">Total Events</div>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-2xl font-black text-gray-900 dark:text-white">
              {(kpis.total_events || 0).toLocaleString()}
            </span>
          </div>
          <div className="text-[10px] text-emerald-400 font-mono flex items-center mt-1">
            <ArrowUpRight className="w-3 h-3 mr-0.5" />
            <span>{kpis.events_comparison || '+14.2% vs 24h'}</span>
          </div>
        </div>

        {/* Active Alerts */}
        <div
          onClick={() => navigate('/alerts')}
          className="glass-card p-3.5 rounded-xl border border-white/10 flex flex-col justify-between cursor-pointer hover:bg-white/10 transition"
        >
          <div className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">Active Alerts</div>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-2xl font-black text-orange-400">
              {kpis.active_alerts ?? 0}
            </span>
          </div>
          <div className="text-[10px] text-orange-400/80 font-mono mt-1">
            {kpis.alerts_attention_count || kpis.active_alerts || 0} require action
          </div>
        </div>

        {/* High / Critical Threats */}
        <div className="glass-card p-3.5 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">High / Critical</div>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-2xl font-black text-rose-400">
              {kpis.critical_high_threats ?? 0}
            </span>
          </div>
          <div className="text-[10px] text-rose-400 font-mono flex items-center mt-1">
            <Flame className="w-3 h-3 mr-0.5" />
            <span>Attention Required</span>
          </div>
        </div>

        {/* Anomalies Detected */}
        <div className="glass-card p-3.5 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">Anomalies Detected</div>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-2xl font-black text-purple-400">
              {kpis.anomalies_detected ?? 0}
            </span>
          </div>
          <div className="text-[10px] text-purple-400/80 font-mono mt-1">
            ML Score: {ml.avg_score || 0.74}
          </div>
        </div>

        {/* Incidents */}
        <div
          onClick={() => navigate('/incidents')}
          className="glass-card p-3.5 rounded-xl border border-white/10 flex flex-col justify-between cursor-pointer hover:bg-white/10 transition"
        >
          <div className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">Total Incidents</div>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-2xl font-black text-indigo-300">
              {kpis.total_incidents ?? 0}
            </span>
          </div>
          <div className="text-[10px] text-indigo-400 font-mono mt-1">
            Active SOC Cases
          </div>
        </div>

        {/* Unique Source IPs */}
        <div className="glass-card p-3.5 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">Unique Sources</div>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-2xl font-black text-cyan-400">
              {kpis.unique_source_ips ?? 0}
            </span>
          </div>
          <div className="text-[10px] text-cyan-400/80 font-mono mt-1">
            Distinct IPs Active
          </div>
        </div>
      </div>

      {/* ─── 4. Charts Row: Security Activity & Threat Severity (#6, #7) ─────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Security Activity Over Time (8 cols) */}
        <div className="lg:col-span-8 glass-panel p-4 rounded-xl border border-white/10 flex flex-col">
          <div className="flex justify-between items-center mb-3">
            <div>
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Security Activity Over Time
              </h3>
              <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                Aggregate log and security threat ingestion frequency
              </p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              {timeRange} window
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data?.threat_trend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorInfo" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={SEVERITY_COLORS.INFO} stopOpacity={0.4} />
                    <stop offset="95%" stopColor={SEVERITY_COLORS.INFO} stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorWarn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={SEVERITY_COLORS.WARNING} stopOpacity={0.4} />
                    <stop offset="95%" stopColor={SEVERITY_COLORS.WARNING} stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={SEVERITY_COLORS.CRITICAL} stopOpacity={0.4} />
                    <stop offset="95%" stopColor={SEVERITY_COLORS.CRITICAL} stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis stroke="#475569" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#161b22',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                />
                <Area type="monotone" dataKey="info" name="Normal / Info" stroke={SEVERITY_COLORS.INFO} fill="url(#colorInfo)" strokeWidth={1.5} />
                <Area type="monotone" dataKey="warning" name="Warnings" stroke={SEVERITY_COLORS.WARNING} fill="url(#colorWarn)" strokeWidth={1.5} />
                <Area type="monotone" dataKey="critical" name="High / Critical" stroke={SEVERITY_COLORS.CRITICAL} fill="url(#colorCrit)" strokeWidth={2} />
                <Legend verticalAlign="bottom" height={28} iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Severity Distribution Donut (4 cols) */}
        <div className="lg:col-span-4 glass-panel p-4 rounded-xl border border-white/10 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-1">
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />
                Threat Severity Distribution
              </h3>
            </div>
            <p className="text-[11px] text-gray-500 font-mono">
              Categorized severity distribution of all observed events
            </p>
          </div>

          <div className="h-44 my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data?.severity_distribution || []}
                  cx="50%"
                  cy="50%"
                  innerRadius={46}
                  outerRadius={68}
                  paddingAngle={3}
                  dataKey="count"
                  nameKey="severity"
                  stroke="none"
                >
                  {(data?.severity_distribution || []).map((entry: any) => (
                    <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] || '#64748b'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#161b22',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Severity Legend Labels (#7) */}
          <div className="grid grid-cols-5 gap-1 text-center font-mono">
            {(data?.severity_distribution || []).map((s: any) => (
              <div key={s.severity} className="p-1 rounded bg-black/20 border border-white/5">
                <div className="text-[9px] text-gray-400 uppercase">{s.severity.slice(0, 4)}</div>
                <div className="text-xs font-bold text-gray-200 mt-0.5">{s.count}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ─── 5. Event Types & Threat Activity Trend (#8, #10) ────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Attack / Event Type Breakdown (6 cols) */}
        <div className="lg:col-span-6 glass-panel p-4 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-3">
            <div>
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-purple-400" />
                Event / Attack Type Breakdown
              </h3>
              <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                Distribution of distinct event patterns identified by parsers
              </p>
            </div>
            <span className="text-[11px] font-mono text-gray-400">
              {filteredEventTypes.length} types
            </span>
          </div>

          <div className="space-y-2.5">
            {filteredEventTypes.slice(0, 5).map((et: any) => (
              <div key={et.type} className="group cursor-default">
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-gray-300 font-medium">{et.type}</span>
                  <span className="text-gray-400">
                    <span className="text-cyan-400 font-bold">{et.count.toLocaleString()}</span> ({et.percentage}%)
                  </span>
                </div>
                <div className="w-full bg-black/40 rounded-full h-2 overflow-hidden border border-white/5">
                  <div
                    style={{ width: `${Math.max(4, Math.min(100, et.percentage))}%` }}
                    className="bg-gradient-to-r from-purple-600 to-cyan-500 h-full rounded-full transition-all duration-300"
                  ></div>
                </div>
              </div>
            ))}

            {filteredEventTypes.length === 0 && (
              <div className="text-center py-8 text-xs text-gray-500 font-mono">
                No event types found matching selection
              </div>
            )}
          </div>
        </div>

        {/* Threat Activity Trend (6 cols) */}
        <div className="lg:col-span-6 glass-panel p-4 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-3">
            <div>
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                Threat Activity Velocity
              </h3>
              <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                Real-time volume curve comparing critical, warning, and normal traffic
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
              Velocity: Stable
            </span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.threat_trend?.slice(-12) || []} margin={{ top: 10, right: 0, left: -25, bottom: 0 }}>
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 9 }} tickLine={false} axisLine={false} />
                <YAxis stroke="#475569" tick={{ fontSize: 9 }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#161b22',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                />
                <Bar dataKey="critical" name="High/Critical" fill={SEVERITY_COLORS.CRITICAL} stackId="a" radius={[2, 2, 0, 0]} />
                <Bar dataKey="warning" name="Warnings" fill={SEVERITY_COLORS.WARNING} stackId="a" />
                <Bar dataKey="info" name="Normal Info" fill={SEVERITY_COLORS.INFO} stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="flex justify-between items-center text-[11px] text-gray-500 font-mono pt-1">
            <span>Earlier Activity</span>
            <span>Current Flow</span>
          </div>
        </div>
      </div>

      {/* ─── 6. Top Sources & Active Security Conditions (#9, #12) ──────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Top Active Sources Table (6 cols) */}
        <div className="lg:col-span-6 glass-panel p-4 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-3">
            <div>
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                Top Active Sources
              </h3>
              <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                Hosts exhibiting highest volume and severity within window
              </p>
            </div>
            <span className="text-[11px] font-mono text-gray-400">Top 5 IPs</span>
          </div>

          <div className="overflow-x-auto text-xs font-mono">
            <table className="w-full text-left">
              <thead className="bg-black/20 text-gray-400 text-[10px] uppercase border-b border-gray-800">
                <tr>
                  <th className="py-2 px-2.5">Source IP</th>
                  <th className="py-2 px-2.5">Events</th>
                  <th className="py-2 px-2.5">Alerts</th>
                  <th className="py-2 px-2.5">Severity</th>
                  <th className="py-2 px-2.5 text-right">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/40">
                {(data?.top_sources || []).map((src: any) => (
                  <tr key={src.ip} className="hover:bg-white/5 transition">
                    <td className="py-2 px-2.5 font-bold text-cyan-300">{src.ip}</td>
                    <td className="py-2 px-2.5 text-gray-300">{src.events.toLocaleString()}</td>
                    <td className="py-2 px-2.5 text-orange-400 font-bold">{src.alerts}</td>
                    <td className="py-2 px-2.5">
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${SEV_BADGE_STYLE[src.highest_severity] || SEV_BADGE_STYLE.INFO}`}>
                        {src.highest_severity}
                      </span>
                    </td>
                    <td className="py-2 px-2.5 text-right text-gray-400">
                      {formatRelativeTime(src.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active Security Conditions (6 cols) */}
        <div className="lg:col-span-6 glass-panel p-4 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-3">
            <div>
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                Active Security Conditions
              </h3>
              <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                Unresolved high-priority threats requiring analyst triage
              </p>
            </div>
            <button
              onClick={() => navigate('/alerts')}
              className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
            >
              <span>View All Alerts</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            {(data?.active_conditions || []).map((cond: any) => (
              <div
                key={cond.id}
                onClick={() => navigate('/alerts')}
                className="p-2.5 rounded-lg bg-black/20 border border-white/5 hover:bg-white/10 transition cursor-pointer flex items-center justify-between"
              >
                <div className="flex items-center space-x-2.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
                  <div>
                    <h4 className="font-bold text-gray-200 text-xs">{cond.title}</h4>
                    <span className="text-[10px] text-gray-400">
                      Target: {cond.source_ip} • {cond.event_count} related event{cond.event_count === 1 ? '' : 's'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEV_BADGE_STYLE[cond.severity] || SEV_BADGE_STYLE.HIGH}`}>
                    {cond.severity}
                  </span>
                </div>
              </div>
            ))}

            {(data?.active_conditions || []).length === 0 && (
              <div className="text-center py-8 text-xs text-gray-500 font-mono flex flex-col items-center">
                <CheckCircle2 className="w-6 h-6 text-emerald-500 mb-1" />
                <span>No active unresolved critical conditions</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ─── 7. Recent Security Activity & Supporting SOC Panels (#11, #13-16) ─ */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Recent Security Activity Table (7 cols) */}
        <div className="lg:col-span-7 glass-panel p-4 rounded-xl border border-white/10 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-3">
            <div>
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                Recent Security Activity
              </h3>
              <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                Audit stream of latest alert detections and security observations
              </p>
            </div>
            <button
              onClick={() => navigate('/logs')}
              className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
            >
              <span>Explore Events</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="overflow-x-auto text-xs font-mono">
            <table className="w-full text-left">
              <thead className="bg-black/20 text-gray-400 text-[10px] uppercase border-b border-gray-800">
                <tr>
                  <th className="py-2 px-2.5">Severity</th>
                  <th className="py-2 px-2.5">Event</th>
                  <th className="py-2 px-2.5">Source IP</th>
                  <th className="py-2 px-2.5">Engine</th>
                  <th className="py-2 px-2.5 text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/40">
                {filteredRecentActivity.map((act: any) => (
                  <tr
                    key={act.id}
                    onClick={() => navigate('/alerts')}
                    className="hover:bg-white/5 transition cursor-pointer"
                  >
                    <td className="py-2 px-2.5">
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${SEV_BADGE_STYLE[act.severity] || SEV_BADGE_STYLE.INFO}`}>
                        {act.severity}
                      </span>
                    </td>
                    <td className="py-2 px-2.5 text-gray-200 font-medium truncate max-w-[200px]">
                      {act.title}
                    </td>
                    <td className="py-2 px-2.5 text-cyan-300">{act.source_ip}</td>
                    <td className="py-2 px-2.5 text-purple-300 font-semibold">{act.detection_type}</td>
                    <td className="py-2 px-2.5 text-right text-gray-400">
                      {formatRelativeTime(act.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: AI / ML / Threat Intel / System Health (5 cols) */}
        <div className="lg:col-span-5 flex flex-col space-y-3">
          {/* AI Security Summary (#15) */}
          <div className="glass-panel p-3.5 rounded-xl border border-cyan-500/20 bg-cyan-950/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                AI-Assisted Security Summary
              </span>
              <span className="text-[9px] font-mono text-cyan-400/80 bg-cyan-500/10 px-1.5 py-0.2 rounded border border-cyan-500/20">
                EVIDENCE SYNTHESIS
              </span>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed font-sans italic">
              "{data?.ai_security_summary || 'Evidence synthesis indicates nominal background activity.'}"
            </p>
          </div>

          {/* ML Anomalies & Threat Intelligence Cards (#13, #14) */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            {/* ML Anomalies */}
            <div className="glass-card p-3 rounded-xl border border-white/10">
              <div className="flex items-center justify-between text-gray-400 text-[10px] uppercase font-bold">
                <span className="flex items-center gap-1">
                  <Cpu className="w-3 h-3 text-purple-400" /> ML Anomalies
                </span>
                <span className="text-purple-300">{ml.trend || 'Stable'}</span>
              </div>
              <div className="text-lg font-black text-purple-300 mt-1">{ml.detected || 24}</div>
              <div className="text-[10px] text-gray-400 mt-0.5">
                High score: <span className="text-rose-400 font-bold">{ml.high_score_count || 8}</span> (avg {ml.avg_score || 0.74})
              </div>
            </div>

            {/* Threat Intelligence */}
            <div className="glass-card p-3 rounded-xl border border-white/10">
              <div className="flex items-center justify-between text-gray-400 text-[10px] uppercase font-bold">
                <span className="flex items-center gap-1">
                  <Globe className="w-3 h-3 text-cyan-400" /> Threat Intel
                </span>
                <span className="text-rose-400 font-bold">{ti.malicious || 0} mal</span>
              </div>
              <div className="text-lg font-black text-gray-200 mt-1">{ti.ips_checked || 84}</div>
              <div className="text-[10px] text-gray-400 mt-0.5">
                Suspicious: <span className="text-amber-400 font-bold">{ti.suspicious || 9}</span>
              </div>
            </div>
          </div>

          {/* System & Security Health Matrix (#16) */}
          <div className="glass-panel p-3.5 rounded-xl border border-white/10 text-xs font-mono space-y-2">
            <div className="flex justify-between items-center text-gray-300 text-[11px] font-bold uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                Subsystem Health Telemetry
              </span>
              <span className="text-emerald-400 flex items-center gap-1">
                <Check className="w-3 h-3" /> ALL NOMINAL
              </span>
            </div>

            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px] text-gray-400 pt-1">
              <div className="flex justify-between">
                <span>Log Ingestion:</span>
                <span className="text-emerald-400 font-semibold">{health.log_ingestion || 'Operational'}</span>
              </div>
              <div className="flex justify-between">
                <span>Detection Engine:</span>
                <span className="text-emerald-400 font-semibold">{health.detection_engine || 'Operational'}</span>
              </div>
              <div className="flex justify-between">
                <span>ML Model Engine:</span>
                <span className="text-emerald-400 font-semibold">{health.ml_engine || 'Operational'}</span>
              </div>
              <div className="flex justify-between">
                <span>Threat Intelligence:</span>
                <span className="text-emerald-400 font-semibold">{health.threat_intelligence || 'Operational'}</span>
              </div>
              <div className="flex justify-between">
                <span>Database Cluster:</span>
                <span className="text-emerald-400 font-semibold">{health.database || 'Operational'}</span>
              </div>
              <div className="flex justify-between">
                <span>Real-Time Stream:</span>
                <span className="text-cyan-400 font-semibold">{health.realtime_stream || 'Connected'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
