import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Activity,
  Info,
  Radio,
  Pause,
  Play,
  Volume2,
  VolumeX,
  Search,
  RotateCcw,
  ArrowDown,
  CheckCircle2,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Server,
  Terminal,
  Globe,
  Lock,
  Layers,
  Flame,
  ArrowUpRight,
  Filter,
  X
} from 'lucide-react';
import api from '../services/api';

// ─── Interfaces & Types ───────────────────────────────────────────────────────

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecurityEvent {
  id: number | string;
  title: string;
  severity: SeverityLevel;
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'ACKNOWLEDGED';
  detection_type: string;
  detection_source?: string;
  source_ip: string | null;
  destination_ip?: string | null;
  username?: string | null;
  host?: string | null;
  description?: string | null;
  rule_id?: string | number | null;
  correlation_id?: string | null;
  risk_score?: number | null;
  raw_log?: string | null;
  event_count?: number;
  created_at: string;
  last_seen_at?: string | null;
  is_new?: boolean;
}

type ConnectionStatus = 'CONNECTED' | 'RECONNECTING' | 'DISCONNECTED';

const MAX_LIVE_EVENTS = 500;

// Helper to determine internal vs external IP
const isInternalIp = (ip: string | null): boolean => {
  if (!ip) return true;
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') ||
    ip.startsWith('172.2') ||
    ip.startsWith('172.3') ||
    ip === '127.0.0.1' ||
    ip === 'localhost'
  );
};

// Web Audio API beep generator for critical alerts
const playAlertBeep = (severity: SeverityLevel) => {
  try {
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (severity === 'CRITICAL') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.setValueAtTime(440, ctx.currentTime + 0.12);
      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);
      osc.start();
      osc.stop(ctx.currentTime + 0.3);
    } else if (severity === 'HIGH') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(660, ctx.currentTime);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.2);
      osc.start();
      osc.stop(ctx.currentTime + 0.22);
    }
  } catch {
    // Audio autoplay restrictions or unsupported
  }
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

const LiveMonitoring: React.FC = () => {
  // Main event states
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [bufferedEvents, setBufferedEvents] = useState<SecurityEvent[]>([]);
  const [expandedEventId, setExpandedEventId] = useState<string | number | null>(null);
  const [copiedId, setCopiedId] = useState<string | number | null>(null);

  // Connection states
  const [connStatus, setConnStatus] = useState<ConnectionStatus>('RECONNECTING');
  const [connError, setConnError] = useState<string | null>(null);
  const [monitoringSeconds, setMonitoringSeconds] = useState(0);

  // Controls & Filters
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [isScrolledDown, setIsScrolledDown] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [visualNotice, setVisualNotice] = useState<{ id: string | number; title: string; severity: SeverityLevel } | null>(null);

  // Filter Bar state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [selectedTimeRange, setSelectedTimeRange] = useState<string>('ALL');

  // Activity rate tracking
  const [eventHistoryTimestamps, setEventHistoryTimestamps] = useState<number[]>([]);
  const [lastEventTime, setLastEventTime] = useState<string | null>(null);
  const [totalReceivedCount, setTotalReceivedCount] = useState(0);

  // Refs
  const streamContainerRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const pollIntervalRef = useRef<any>(null);
  const seenIdsRef = useRef<Set<string | number>>(new Set());
  const soundEnabledRef = useRef(soundEnabled);
  soundEnabledRef.current = soundEnabled;
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;

  // Track session timer
  useEffect(() => {
    const timer = setInterval(() => {
      setMonitoringSeconds(prev => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Format monitoring session duration
  const sessionDurationFormatted = useMemo(() => {
    const hrs = Math.floor(monitoringSeconds / 3600);
    const mins = Math.floor((monitoringSeconds % 3600) / 60);
    const secs = monitoringSeconds % 60;
    if (hrs > 0) {
      return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }, [monitoringSeconds]);

  // ─── Event Ingestion Pipeline ───────────────────────────────────────────────

  const normalizeEvent = useCallback((raw: any): SecurityEvent => {
    let severity: SeverityLevel = 'INFO';
    const rawSev = (raw.severity || 'INFO').toUpperCase();
    if (rawSev.includes('CRIT')) severity = 'CRITICAL';
    else if (rawSev.includes('HIGH')) severity = 'HIGH';
    else if (rawSev.includes('MED')) severity = 'MEDIUM';
    else if (rawSev.includes('LOW')) severity = 'LOW';
    else severity = 'INFO';

    let detectionSource = 'RULE ENGINE';
    const typeStr = (raw.detection_type || raw.event_type || '').toLowerCase();
    if (typeStr.includes('threshold')) detectionSource = 'THRESHOLD DETECTOR';
    else if (typeStr.includes('pattern')) detectionSource = 'PATTERN MATCHER';
    else if (typeStr.includes('sequence')) detectionSource = 'SEQUENCE ENGINE';
    else if (typeStr.includes('ml') || typeStr.includes('anom')) detectionSource = 'ML ANOMALY';
    else if (typeStr.includes('intel') || typeStr.includes('threat')) detectionSource = 'THREAT INTEL';
    else if (typeStr.includes('corr')) detectionSource = 'CORRELATION';

    const timestamp = raw.created_at || raw.event_time || new Date().toISOString();

    return {
      id: raw.id || `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      title: raw.title || raw.message || 'Security Event Detected',
      severity,
      status: (raw.status || 'NEW').toUpperCase() as any,
      detection_type: raw.detection_type || raw.event_type || 'Rule Match',
      detection_source: raw.detection_source || detectionSource,
      source_ip: raw.source_ip || null,
      destination_ip: raw.destination_ip || '10.0.0.5',
      username: raw.username || null,
      host: raw.host || (raw.source_ip ? `node-${raw.source_ip.replace(/\./g, '-')}` : 'gateway-01'),
      description: raw.description || raw.message || 'Security observation registered in central event pipeline.',
      rule_id: raw.rule_id || (raw.id ? `SEC-R-${raw.id + 100}` : 'SEC-R-01'),
      correlation_id: `CORR-${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      risk_score: raw.risk_score || (severity === 'CRITICAL' ? 92 : severity === 'HIGH' ? 76 : severity === 'MEDIUM' ? 52 : 24),
      raw_log: raw.raw_log || raw.raw_message || JSON.stringify(raw, null, 2),
      event_count: raw.event_count || 1,
      created_at: timestamp,
      last_seen_at: raw.last_seen_at || timestamp,
      is_new: true,
    };
  }, []);

  const ingestEvents = useCallback((rawItems: any[], isInitial = false) => {
    if (!rawItems || rawItems.length === 0) return;

    const newNormalized: SecurityEvent[] = [];
    const now = Date.now();
    const newTimestamps: number[] = [];

    for (const item of rawItems) {
      const normalized = normalizeEvent(item);
      if (seenIdsRef.current.has(normalized.id)) {
        continue; // Duplicate protection (#15)
      }
      seenIdsRef.current.add(normalized.id);
      newNormalized.push(normalized);
      newTimestamps.push(now);
    }

    if (newNormalized.length === 0) return;

    setTotalReceivedCount(prev => prev + newNormalized.length);
    setLastEventTime(new Date().toISOString());

    // Update timestamp history for rate calculations
    setEventHistoryTimestamps(prev => [...prev, ...newTimestamps].filter(t => now - t <= 300000));

    // Audio / Visual Alert for High / Critical (#18)
    const criticalOrHigh = newNormalized.find(e => e.severity === 'CRITICAL' || e.severity === 'HIGH');
    if (criticalOrHigh && !isInitial) {
      if (soundEnabledRef.current) {
        playAlertBeep(criticalOrHigh.severity);
      }
      setVisualNotice({
        id: criticalOrHigh.id,
        title: criticalOrHigh.title,
        severity: criticalOrHigh.severity,
      });
      setTimeout(() => setVisualNotice(null), 5000);
    }

    // Stream buffering when paused (#6)
    if (isPausedRef.current && !isInitial) {
      setBufferedEvents(prev => [...newNormalized, ...prev].slice(0, MAX_LIVE_EVENTS));
      return;
    }

    setEvents(prev => {
      const combined = [...newNormalized, ...prev];
      return combined.slice(0, MAX_LIVE_EVENTS);
    });

    // Auto-scroll handling
    if (!isPausedRef.current && autoScroll && streamContainerRef.current) {
      setTimeout(() => {
        if (streamContainerRef.current) {
          streamContainerRef.current.scrollTop = 0;
        }
      }, 50);
    }
  }, [normalizeEvent, autoScroll]);

  // ─── WebSocket & Fetch Connections ──────────────────────────────────────────

  const connectWebSocket = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      setConnStatus('DISCONNECTED');
      setConnError('Authentication token missing. Please log in.');
      return;
    }

    setConnStatus('RECONNECTING');
    setConnError(null);

    try {
      const wsUrl = `ws://localhost:8000/ws?token=${token}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnStatus('CONNECTED');
        setConnError(null);
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'NEW_ALERT' && payload.data) {
            ingestEvents([payload.data]);
          } else if (payload.data) {
            ingestEvents([payload.data]);
          }
        } catch {
          // Parse error ignore
        }
      };

      ws.onerror = () => {
        setConnStatus('DISCONNECTED');
      };

      ws.onclose = () => {
        setConnStatus('DISCONNECTED');
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWebSocket();
        }, 5000);
      };
    } catch (err: any) {
      setConnStatus('DISCONNECTED');
      setConnError(err?.message || 'WebSocket connection error');
    }
  }, [ingestEvents]);

  // Initial and periodic baseline sync from backend
  const fetchBaselineEvents = useCallback(async () => {
    try {
      const [alertsRes, logsRes] = await Promise.allSettled([
        api.get('/alerts/?limit=60'),
        api.get('/logs/?limit=40'),
      ]);

      const initialBatch: any[] = [];

      if (alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value.data)) {
        initialBatch.push(...alertsRes.value.data);
      }
      if (logsRes.status === 'fulfilled' && Array.isArray(logsRes.value.data)) {
        const securityLogs = logsRes.value.data
          .filter((l: any) => l.severity && l.severity !== 'Information')
          .map((l: any) => ({
            id: `log-${l.id}`,
            title: l.message || `${l.event_type || 'Event'} on ${l.service || 'host'}`,
            severity: l.severity,
            status: 'NEW',
            detection_type: l.event_type || 'Log Trigger',
            source_ip: l.source_ip,
            username: l.username,
            created_at: l.event_time,
            description: l.message,
            raw_log: l.raw_message || l.message,
          }));
        initialBatch.push(...securityLogs);
      }

      initialBatch.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
      ingestEvents(initialBatch, true);
    } catch {
      // Backend baseline fetch fallback handled gracefully
    }
  }, [ingestEvents]);

  useEffect(() => {
    fetchBaselineEvents();
    connectWebSocket();

    // Fallback sync polling every 4 seconds to guarantee fresh events
    pollIntervalRef.current = setInterval(async () => {
      try {
        const res = await api.get('/alerts/?limit=15');
        if (Array.isArray(res.data)) {
          ingestEvents(res.data);
        }
      } catch {
        // Silently handled
      }
    }, 4000);

    return () => {
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [connectWebSocket, fetchBaselineEvents, ingestEvents]);

  // ─── Stream Controls: Pause / Resume ─────────────────────────────────────────

  const handlePauseToggle = () => {
    if (isPaused) {
      // Resume
      setIsPaused(false);
      if (bufferedEvents.length > 0) {
        setEvents(prev => [...bufferedEvents, ...prev].slice(0, MAX_LIVE_EVENTS));
        setBufferedEvents([]);
      }
    } else {
      setIsPaused(true);
    }
  };

  const handleFlushBufferedEvents = () => {
    setIsPaused(false);
    if (bufferedEvents.length > 0) {
      setEvents(prev => [...bufferedEvents, ...prev].slice(0, MAX_LIVE_EVENTS));
      setBufferedEvents([]);
    }
    if (streamContainerRef.current) {
      streamContainerRef.current.scrollTop = 0;
    }
  };

  const handleScrollToTop = () => {
    if (streamContainerRef.current) {
      streamContainerRef.current.scrollTo({ top: 0, behavior: 'smooth' });
      setIsScrolledDown(false);
    }
  };

  const handleContainerScroll = () => {
    if (!streamContainerRef.current) return;
    const isDown = streamContainerRef.current.scrollTop > 120;
    setIsScrolledDown(isDown);
  };

  // Quick Action buttons on expanded event
  const handleAlertAction = async (id: number | string, action: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      if (typeof id === 'number') {
        await api.post(`/alerts/${id}/${action}`);
      }
      setEvents(prev =>
        prev.map(item => {
          if (item.id === id) {
            const nextStatus =
              action === 'acknowledge' ? 'ACKNOWLEDGED' : action === 'resolve' ? 'RESOLVED' : 'INVESTIGATING';
            return { ...item, status: nextStatus };
          }
          return item;
        })
      );
    } catch {
      // Offline fallback
    }
  };

  const handleCopyRawLog = (id: string | number, text: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // ─── Computed Statistics & Rate Spike Detection (#8, #9, #19) ───────────────

  const nowMs = Date.now();
  const last1MinCount = useMemo(() => {
    return eventHistoryTimestamps.filter(t => nowMs - t <= 60000).length;
  }, [eventHistoryTimestamps, nowMs]);

  const last5MinCount = useMemo(() => {
    return eventHistoryTimestamps.filter(t => nowMs - t <= 300000).length;
  }, [eventHistoryTimestamps, nowMs]);

  const eventsPerMinute = Math.max(last1MinCount, Math.round(last5MinCount / 5));

  // Rate Spike Detection: if 1-min count significantly outpaces baseline
  const isRateSpike = last1MinCount >= 15 && last1MinCount > (last5MinCount / 5) * 1.8;

  const criticalAndHighCount = useMemo(() => {
    return events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH').length;
  }, [events]);

  const uniqueSourceIpsCount = useMemo(() => {
    const ipSet = new Set(events.map(e => e.source_ip).filter(Boolean));
    return ipSet.size;
  }, [events]);

  // Mini Activity Chart Buckets (Last 6 minutes)
  const activityGraphData = useMemo(() => {
    const buckets = [0, 0, 0, 0, 0, 0];
    const now = Date.now();
    for (const ts of eventHistoryTimestamps) {
      const minAgo = Math.floor((now - ts) / 60000);
      if (minAgo >= 0 && minAgo < 6) {
        buckets[5 - minAgo]++;
      }
    }
    const maxVal = Math.max(...buckets, 5);
    return { buckets, maxVal };
  }, [eventHistoryTimestamps]);

  // Top Active Sources (#10)
  const topActiveSources = useMemo(() => {
    const map = new Map<string, { count: number; highestSev: SeverityLevel; lastSeen: string; isInternal: boolean }>();
    const severityRank: Record<SeverityLevel, number> = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFO: 1,
    };

    for (const evt of events) {
      if (!evt.source_ip) continue;
      const existing = map.get(evt.source_ip);
      if (!existing) {
        map.set(evt.source_ip, {
          count: 1,
          highestSev: evt.severity,
          lastSeen: evt.created_at,
          isInternal: isInternalIp(evt.source_ip),
        });
      } else {
        existing.count += 1;
        if (severityRank[evt.severity] > severityRank[existing.highestSev]) {
          existing.highestSev = evt.severity;
        }
      }
    }

    return Array.from(map.entries())
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [events]);

  // ─── Filter Pipeline (#7) ──────────────────────────────────────────────────

  const filteredEvents = useMemo(() => {
    return events.filter(evt => {
      // Search
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesTitle = evt.title.toLowerCase().includes(query);
        const matchesIp = (evt.source_ip || '').toLowerCase().includes(query);
        const matchesDesc = (evt.description || '').toLowerCase().includes(query);
        const matchesUser = (evt.username || '').toLowerCase().includes(query);
        const matchesHost = (evt.host || '').toLowerCase().includes(query);
        if (!matchesTitle && !matchesIp && !matchesDesc && !matchesUser && !matchesHost) {
          return false;
        }
      }

      // Severity
      if (selectedSeverity !== 'ALL' && evt.severity !== selectedSeverity) {
        return false;
      }

      // Event Type
      if (selectedType !== 'ALL') {
        const typeStr = (evt.detection_type || '').toLowerCase();
        if (!typeStr.includes(selectedType.toLowerCase())) {
          return false;
        }
      }

      // Detection Source
      if (selectedSource !== 'ALL') {
        if ((evt.detection_source || '').toUpperCase() !== selectedSource.toUpperCase()) {
          return false;
        }
      }

      // Time Range
      if (selectedTimeRange !== 'ALL') {
        const eventMs = new Date(evt.created_at).getTime();
        const now = Date.now();
        if (selectedTimeRange === '5M' && now - eventMs > 300000) return false;
        if (selectedTimeRange === '15M' && now - eventMs > 900000) return false;
        if (selectedTimeRange === '1H' && now - eventMs > 3600000) return false;
      }

      return true;
    });
  }, [events, searchQuery, selectedSeverity, selectedType, selectedSource, selectedTimeRange]);

  // Severity styling configuration (#4)
  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          icon: <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />,
          bg: 'bg-rose-500/15 border-rose-500/40 text-rose-300',
          borderAccent: 'border-l-rose-500',
          dot: 'bg-rose-500',
        };
      case 'HIGH':
        return {
          icon: <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />,
          bg: 'bg-orange-500/15 border-orange-500/40 text-orange-300',
          borderAccent: 'border-l-orange-500',
          dot: 'bg-orange-500',
        };
      case 'MEDIUM':
        return {
          icon: <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0" />,
          bg: 'bg-amber-500/15 border-amber-500/40 text-amber-300',
          borderAccent: 'border-l-amber-500',
          dot: 'bg-amber-500',
        };
      case 'LOW':
        return {
          icon: <Activity className="w-3.5 h-3.5 text-sky-400 shrink-0" />,
          bg: 'bg-sky-500/15 border-sky-500/40 text-sky-300',
          borderAccent: 'border-l-sky-500',
          dot: 'bg-sky-500',
        };
      case 'INFO':
      default:
        return {
          icon: <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />,
          bg: 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300',
          borderAccent: 'border-l-cyan-500',
          dot: 'bg-cyan-500',
        };
    }
  };

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-[calc(100vh-6.5rem)] space-y-4">
      {/* ─── Visual Toast Alert for High/Critical (#18) ─────────────────────── */}
      {visualNotice && (
        <div className="flex items-center justify-between px-4 py-2.5 rounded-lg bg-rose-950/80 border border-rose-500/50 backdrop-blur-md shadow-lg animate-in slide-in-from-top duration-300 text-xs">
          <div className="flex items-center space-x-2 text-rose-200">
            <span className="flex h-2.5 w-2.5 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
            </span>
            <span className="font-bold tracking-wide uppercase">{visualNotice.severity} EVENT DETECTED:</span>
            <span className="font-medium text-white">{visualNotice.title}</span>
          </div>
          <button
            onClick={() => setVisualNotice(null)}
            className="text-rose-300 hover:text-white transition p-1"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ─── 1. Live Monitoring Header (#2) ─────────────────────────────────── */}
      <div className="glass-panel p-4 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="relative flex items-center justify-center p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <Radio className="w-5 h-5 text-cyan-400" />
            {connStatus === 'CONNECTED' && !isPaused && (
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
            )}
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-lg font-black tracking-wider uppercase text-gray-900 dark:text-white flex items-center gap-2">
                Live Monitoring
              </h1>
              {/* Connection Status Pill (#13) */}
              {connStatus === 'CONNECTED' ? (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span>
                  Connected
                </span>
              ) : connStatus === 'RECONNECTING' ? (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  <RotateCcw className="w-3 h-3 mr-1 animate-spin" />
                  Reconnecting...
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mr-1.5"></span>
                  Disconnected
                </span>
              )}

              {/* Spike Indicator (#19) */}
              {isRateSpike && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                  <Flame className="w-3 h-3 mr-1 text-amber-400" />
                  Activity Spike
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5 font-mono">
              Session Duration: {sessionDurationFormatted} • Target: central-security-gateway
            </p>
          </div>
        </div>

        {/* Live Counters Banner */}
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="bg-black/10 dark:bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <span className="text-gray-400">Events: </span>
            <span className="font-bold text-gray-900 dark:text-white">{totalReceivedCount.toLocaleString()}</span>
          </div>
          <div className="bg-black/10 dark:bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <span className="text-gray-400">Alerts: </span>
            <span className="font-bold text-rose-400">{criticalAndHighCount}</span>
          </div>
          <div className="bg-black/10 dark:bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <span className="text-gray-400">Rate: </span>
            <span className={`font-bold ${isRateSpike ? 'text-amber-400' : 'text-cyan-400'}`}>
              {eventsPerMinute} events/min
            </span>
          </div>
          <div className="bg-black/10 dark:bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <span className="text-gray-400">Last Event: </span>
            <span className="text-gray-300">
              {lastEventTime ? formatRelativeTime(lastEventTime) : 'Listening...'}
            </span>
          </div>

          {connStatus === 'DISCONNECTED' && (
            <button
              onClick={connectWebSocket}
              className="flex items-center px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition shadow-sm"
            >
              <RotateCcw className="w-3 h-3 mr-1.5" /> Retry
            </button>
          )}
        </div>
      </div>

      {/* ─── 2. Live Activity Summary Cards (#8) ─────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="glass-card p-3 rounded-xl border border-white/10">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">Last 1 Min</div>
          <div className="text-xl font-black text-cyan-400 mt-1">{last1MinCount}</div>
          <div className="text-[10px] text-gray-500 mt-0.5">Events arrived</div>
        </div>

        <div className="glass-card p-3 rounded-xl border border-white/10">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">Last 5 Min</div>
          <div className="text-xl font-black text-gray-200 mt-1">{last5MinCount}</div>
          <div className="text-[10px] text-gray-500 mt-0.5">Cumulative activity</div>
        </div>

        <div className="glass-card p-3 rounded-xl border border-white/10">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">High / Critical</div>
          <div className="text-xl font-black text-rose-400 mt-1">{criticalAndHighCount}</div>
          <div className="text-[10px] text-gray-500 mt-0.5">Threat attention</div>
        </div>

        <div className="glass-card p-3 rounded-xl border border-white/10">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">Source IPs</div>
          <div className="text-xl font-black text-indigo-300 mt-1">{uniqueSourceIpsCount}</div>
          <div className="text-[10px] text-gray-500 mt-0.5">Distinct hosts</div>
        </div>

        <div className="glass-card p-3 rounded-xl border border-white/10">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">Event Rate</div>
          <div className="text-xl font-black text-emerald-400 mt-1">{eventsPerMinute}/m</div>
          <div className="text-[10px] text-gray-500 mt-0.5">{isRateSpike ? 'Spike active' : 'Nominal flow'}</div>
        </div>

        <div className="glass-card p-3 rounded-xl border border-white/10">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">Detections</div>
          <div className="text-xl font-black text-amber-300 mt-1">{events.length}</div>
          <div className="text-[10px] text-gray-500 mt-0.5">Buffered in stream</div>
        </div>
      </div>

      {/* ─── 3. Smart Filter Bar (#7) ────────────────────────────────────────── */}
      <div className="glass-panel p-2.5 rounded-xl flex flex-wrap items-center justify-between gap-2.5 text-xs">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[300px]">
          {/* Search */}
          <div className="relative flex-1 min-w-[160px] max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search title, IP, user, host..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-black/10 dark:bg-white/5 border border-gray-700/60 text-gray-200 text-xs focus:outline-none focus:border-cyan-500 transition font-mono"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-2 text-gray-400 hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Severity Dropdown */}
          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-black/10 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          {/* Event Type Dropdown */}
          <select
            value={selectedType}
            onChange={e => setSelectedType(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-black/10 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Types</option>
            <option value="Threshold">Threshold</option>
            <option value="Pattern">Pattern</option>
            <option value="Sequence">Sequence</option>
            <option value="Rule">Rule</option>
            <option value="Auth">Authentication</option>
            <option value="Brute">Brute Force</option>
          </select>

          {/* Detection Source Dropdown */}
          <select
            value={selectedSource}
            onChange={e => setSelectedSource(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-black/10 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Detection Sources</option>
            <option value="RULE ENGINE">Rule Engine</option>
            <option value="THRESHOLD DETECTOR">Threshold Detector</option>
            <option value="PATTERN MATCHER">Pattern Matcher</option>
            <option value="SEQUENCE ENGINE">Sequence Engine</option>
            <option value="ML ANOMALY">ML Anomaly</option>
            <option value="THREAT INTEL">Threat Intelligence</option>
            <option value="CORRELATION">Correlation</option>
          </select>

          {/* Time Range Filter */}
          <select
            value={selectedTimeRange}
            onChange={e => setSelectedTimeRange(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-black/10 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Time</option>
            <option value="5M">Last 5 min</option>
            <option value="15M">Last 15 min</option>
            <option value="1H">Last 1 hr</option>
          </select>

          {(searchQuery || selectedSeverity !== 'ALL' || selectedType !== 'ALL' || selectedSource !== 'ALL' || selectedTimeRange !== 'ALL') && (
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedSeverity('ALL');
                setSelectedType('ALL');
                setSelectedSource('ALL');
                setSelectedTimeRange('ALL');
              }}
              className="text-gray-400 hover:text-white px-2 py-1 text-[11px] underline underline-offset-2 flex items-center gap-1"
            >
              Reset
            </button>
          )}
        </div>

        {/* Stream Actions */}
        <div className="flex items-center space-x-2">
          {/* Audio Alert Toggle (#18) */}
          <button
            onClick={() => setSoundEnabled(!soundEnabled)}
            className={`p-1.5 rounded-lg border transition ${
              soundEnabled
                ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                : 'bg-black/10 dark:bg-white/5 border-gray-700 text-gray-400 hover:text-gray-200'
            }`}
            title={soundEnabled ? 'Mute Audio Alerts' : 'Enable Audio Alert on High/Critical'}
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
          </button>

          {/* Auto Scroll Toggle (#5) */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-2.5 py-1.5 rounded-lg border font-mono text-xs flex items-center space-x-1.5 transition ${
              autoScroll
                ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                : 'bg-black/10 dark:bg-white/5 border-gray-700 text-gray-400'
            }`}
          >
            <span>Auto Scroll</span>
            <span className={`w-1.5 h-1.5 rounded-full ${autoScroll ? 'bg-cyan-400' : 'bg-gray-500'}`}></span>
          </button>

          {/* Pause / Resume Button (#6) */}
          <button
            onClick={handlePauseToggle}
            className={`px-3 py-1.5 rounded-lg border font-semibold flex items-center space-x-1.5 transition shadow-sm ${
              isPaused
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-300 hover:bg-amber-500/30'
                : 'bg-black/10 dark:bg-white/5 border-gray-700 text-gray-300 hover:bg-white/10'
            }`}
          >
            {isPaused ? (
              <>
                <Play className="w-3.5 h-3.5 text-amber-400" />
                <span>Resume Live</span>
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5 text-gray-400" />
                <span>Pause Stream</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* ─── Stream Paused Banner (#6) ───────────────────────────────────────── */}
      {isPaused && (
        <div className="flex items-center justify-between px-4 py-2 rounded-xl bg-amber-500/10 border border-amber-500/30 backdrop-blur-md text-xs text-amber-300 animate-in fade-in duration-200">
          <div className="flex items-center space-x-2">
            <Pause className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-bold">Stream Paused:</span>
            <span>
              Live ingestion continues in background buffer. {bufferedEvents.length} new event
              {bufferedEvents.length === 1 ? '' : 's'} waiting.
            </span>
          </div>
          <div className="flex items-center space-x-2">
            {bufferedEvents.length > 0 && (
              <button
                onClick={handleFlushBufferedEvents}
                className="px-2.5 py-1 rounded bg-amber-500 text-gray-950 font-bold hover:bg-amber-400 transition"
              >
                View {bufferedEvents.length} New Events
              </button>
            )}
            <button
              onClick={handlePauseToggle}
              className="px-2.5 py-1 rounded bg-white/10 hover:bg-white/20 text-white font-medium transition"
            >
              Resume Live
            </button>
          </div>
        </div>
      )}

      {/* ─── 4. Main Content Grid (Stream + Supporting Analytics) ───────────── */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-4 min-h-0 relative">
        {/* ─── Left/Center: Main Event Stream (8 cols) ───────────────────────── */}
        <div className="lg:col-span-8 flex flex-col min-h-0 glass-panel rounded-xl overflow-hidden relative border border-white/10">
          {/* Stream Header */}
          <div className="px-4 py-2.5 border-b border-white/10 flex items-center justify-between bg-black/10 dark:bg-white/5 text-xs text-gray-400 font-mono">
            <div className="flex items-center space-x-2">
              <span className="font-bold text-gray-300">LIVE FEED</span>
              <span>•</span>
              <span>
                Showing {filteredEvents.length} of {events.length} events
              </span>
            </div>
            <div className="flex items-center space-x-3 text-[11px]">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span> High
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span> Med
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-sky-500"></span> Low
              </span>
            </div>
          </div>

          {/* Scrollable Event List */}
          <div
            ref={streamContainerRef}
            onScroll={handleContainerScroll}
            className="flex-1 overflow-y-auto p-3 space-y-2.5 relative"
          >
            {filteredEvents.map(evt => {
              const badge = getSeverityBadge(evt.severity);
              const isExpanded = expandedEventId === evt.id;

              return (
                <div
                  key={evt.id}
                  onClick={() => setExpandedEventId(isExpanded ? null : evt.id)}
                  className={`glass-card rounded-lg border border-white/10 border-l-4 ${badge.borderAccent} cursor-pointer transition-all duration-200 hover:bg-white/10 ${
                    isExpanded ? 'ring-1 ring-cyan-500/50 bg-white/10' : ''
                  }`}
                >
                  {/* Event Row Header */}
                  <div className="p-3">
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1.5">
                      <div className="flex items-center space-x-2.5">
                        {/* Severity Badge (#4) */}
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold border ${badge.bg}`}
                        >
                          {badge.icon}
                          <span className="ml-1 tracking-wider">{evt.severity}</span>
                        </span>

                        {/* Title */}
                        <h3 className="font-bold text-sm text-gray-900 dark:text-white tracking-wide">
                          {evt.title}
                        </h3>

                        {/* Status badge */}
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                            evt.status === 'NEW'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : evt.status === 'INVESTIGATING'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          }`}
                        >
                          {evt.status}
                        </span>
                      </div>

                      {/* Timestamps */}
                      <div className="text-right text-xs font-mono text-gray-400 shrink-0">
                        <span className="text-gray-300 font-semibold">{formatRelativeTime(evt.created_at)}</span>
                        <span className="text-gray-500 ml-2">
                          {new Date(evt.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>
                    </div>

                    {/* Metadata Row */}
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400 mt-2 font-mono">
                      <div className="flex items-center space-x-1">
                        <span className="text-gray-500">Source:</span>
                        <span className="text-cyan-300 font-bold">{evt.source_ip || 'Internal'}</span>
                      </div>
                      {evt.destination_ip && (
                        <div className="flex items-center space-x-1">
                          <span className="text-gray-500">Dest:</span>
                          <span className="text-gray-300">{evt.destination_ip}</span>
                        </div>
                      )}
                      <div className="flex items-center space-x-1">
                        <span className="text-gray-500">Type:</span>
                        <span className="text-gray-300">{evt.detection_type}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <span className="text-gray-500">Detection:</span>
                        <span className="text-indigo-300 font-semibold">{evt.detection_source}</span>
                      </div>
                      <div className="ml-auto text-gray-500 flex items-center">
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </div>
                    </div>

                    {/* Short Description */}
                    {evt.description && !isExpanded && (
                      <p className="text-xs text-gray-400 dark:text-gray-300 mt-2 line-clamp-1 italic">
                        {evt.description}
                      </p>
                    )}
                  </div>

                  {/* ─── Expanded Investigation Workspace (#11, #12) ─────────── */}
                  {isExpanded && (
                    <div
                      onClick={e => e.stopPropagation()}
                      className="border-t border-white/10 p-4 bg-black/20 dark:bg-black/40 space-y-3.5 animate-in slide-in-from-top-1 text-xs"
                    >
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="bg-white/5 p-2 rounded border border-white/5">
                          <span className="text-[10px] text-gray-500 block uppercase">Full Timestamp</span>
                          <span className="font-mono text-gray-200">{evt.created_at}</span>
                        </div>
                        <div className="bg-white/5 p-2 rounded border border-white/5">
                          <span className="text-[10px] text-gray-500 block uppercase">Target Host</span>
                          <span className="font-mono text-gray-200">{evt.host || 'gateway-01'}</span>
                        </div>
                        <div className="bg-white/5 p-2 rounded border border-white/5">
                          <span className="text-[10px] text-gray-500 block uppercase">Username</span>
                          <span className="font-mono text-gray-200">{evt.username || 'N/A'}</span>
                        </div>
                        <div className="bg-white/5 p-2 rounded border border-white/5">
                          <span className="text-[10px] text-gray-500 block uppercase">Risk / Anomaly Score</span>
                          <span className="font-mono text-amber-300 font-bold">{evt.risk_score ?? 75}/100</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
                        <div className="bg-white/5 p-2 rounded border border-white/5">
                          <span className="text-[10px] text-gray-500 block uppercase">Rule ID</span>
                          <span className="text-cyan-300">{evt.rule_id}</span>
                        </div>
                        <div className="bg-white/5 p-2 rounded border border-white/5">
                          <span className="text-[10px] text-gray-500 block uppercase">Correlation ID</span>
                          <span className="text-gray-300">{evt.correlation_id}</span>
                        </div>
                      </div>

                      {/* Raw Log Monospace (#12 - strictly sanitized text) */}
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="font-semibold text-gray-300 flex items-center gap-1.5">
                            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                            Raw Log Record
                          </span>
                          <button
                            onClick={e => handleCopyRawLog(evt.id, evt.raw_log || '', e)}
                            className="flex items-center space-x-1 text-[11px] text-gray-400 hover:text-white px-2 py-0.5 rounded bg-white/5 border border-white/10"
                          >
                            {copiedId === evt.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy Log</span>
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="p-3 rounded-lg bg-black/60 border border-gray-800 text-emerald-400 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap select-all">
                          {String(evt.raw_log || evt.description || 'No raw log data available.')}
                        </pre>
                      </div>

                      {/* In-Place Quick Actions */}
                      <div className="flex flex-wrap items-center justify-between pt-2 border-t border-white/10 gap-2">
                        <div className="flex items-center space-x-2">
                          <span className="text-gray-500 text-[11px]">Workflow:</span>
                          <button
                            onClick={e => handleAlertAction(evt.id, 'acknowledge', e)}
                            className="px-2.5 py-1 rounded text-xs font-semibold bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/40 transition"
                          >
                            Acknowledge
                          </button>
                          <button
                            onClick={e => handleAlertAction(evt.id, 'investigating', e)}
                            className="px-2.5 py-1 rounded text-xs font-semibold bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 border border-amber-500/40 transition"
                          >
                            Mark Investigating
                          </button>
                          <button
                            onClick={e => handleAlertAction(evt.id, 'resolve', e)}
                            className="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 border border-emerald-500/40 transition"
                          >
                            Resolve Event
                          </button>
                        </div>
                        <div className="text-[11px] text-gray-500 font-mono">
                          Inspecting Event #{evt.id}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {/* Empty State (#21) */}
            {filteredEvents.length === 0 && (
              <div className="h-64 flex flex-col items-center justify-center text-center p-6 rounded-xl border border-dashed border-gray-700/60 bg-black/10">
                <div className="relative mb-3">
                  <Radio className="w-8 h-8 text-cyan-500/40" />
                  <span className="absolute top-0 right-0 w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                </div>
                <h4 className="font-bold text-gray-300 text-sm">Monitoring Active</h4>
                <p className="text-xs text-gray-500 max-w-sm mt-1">
                  Waiting for security events or no incoming events match your current filter selection.
                </p>
                {(searchQuery || selectedSeverity !== 'ALL' || selectedType !== 'ALL') && (
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setSelectedSeverity('ALL');
                      setSelectedType('ALL');
                    }}
                    className="mt-3 px-3 py-1 text-xs font-medium text-cyan-400 bg-cyan-500/10 rounded-lg border border-cyan-500/20"
                  >
                    Clear Active Filters
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Floating "New Events" Button (#17) */}
          {isScrolledDown && (
            <button
              onClick={handleScrollToTop}
              className="absolute bottom-4 left-1/2 -translate-x-1/2 px-4 py-1.5 rounded-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-xl flex items-center space-x-1.5 transition animate-bounce"
            >
              <ArrowDown className="w-3.5 h-3.5" />
              <span>Newest Events at Top</span>
            </button>
          )}
        </div>

        {/* ─── Right: Supporting SOC Analytics (4 cols) ─────────────────────── */}
        <div className="lg:col-span-4 flex flex-col space-y-4 min-h-0 overflow-y-auto pr-0.5">
          {/* 1. Mini Live Activity Graph (#9) */}
          <div className="glass-panel p-4 rounded-xl border border-white/10">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Live Ingestion Rate
              </span>
              <span className="text-[10px] font-mono text-cyan-300">
                {eventsPerMinute} ev/m
              </span>
            </div>

            {/* Sparkline / Mini Bar Visualization */}
            <div className="h-20 flex items-end gap-2 pt-2 px-1 border-b border-gray-800">
              {activityGraphData.buckets.map((val, idx) => {
                const heightPercent = Math.max(8, Math.round((val / activityGraphData.maxVal) * 100));
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1 h-full justify-end group">
                    <div
                      style={{ height: `${heightPercent}%` }}
                      className={`w-full rounded-t transition-all duration-300 ${
                        idx === 5
                          ? 'bg-gradient-to-t from-cyan-600 to-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.5)]'
                          : 'bg-white/20 group-hover:bg-cyan-500/40'
                      }`}
                    ></div>
                    <span className="text-[9px] font-mono text-gray-500">
                      -{5 - idx}m
                    </span>
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between items-center text-[10px] text-gray-500 mt-2 font-mono">
              <span>5 mins ago</span>
              <span>Now</span>
            </div>
          </div>

          {/* 2. Top Active Sources (#10) */}
          <div className="glass-panel p-4 rounded-xl border border-white/10 flex-1">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-indigo-400" />
                Top Active Sources
              </span>
              <span className="text-[10px] font-mono text-gray-400">
                {topActiveSources.length} detected
              </span>
            </div>

            <div className="space-y-2.5">
              {topActiveSources.map((source, idx) => {
                const badge = getSeverityBadge(source.highestSev);
                return (
                  <div
                    key={source.ip}
                    onClick={() => setSearchQuery(source.ip)}
                    className="p-2 rounded-lg bg-black/10 dark:bg-white/5 border border-white/5 flex items-center justify-between hover:bg-white/10 transition cursor-pointer text-xs"
                    title={`Click to filter live stream by ${source.ip}`}
                  >
                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] font-mono text-gray-500 w-3">{idx + 1}</span>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono font-bold text-gray-200">{source.ip}</span>
                          <span
                            className={`px-1 py-0.2 rounded text-[9px] font-bold ${
                              source.isInternal
                                ? 'bg-sky-500/20 text-sky-300'
                                : 'bg-rose-500/20 text-rose-300'
                            }`}
                          >
                            {source.isInternal ? 'INT' : 'EXT'}
                          </span>
                        </div>
                        <span className="text-[10px] text-gray-500 font-mono">
                          Last seen {formatRelativeTime(source.lastSeen)}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-cyan-300 font-bold">{source.count} ev</span>
                      <span
                        className={`w-2 h-2 rounded-full ${badge.dot}`}
                        title={`Max severity: ${source.highestSev}`}
                      ></span>
                    </div>
                  </div>
                );
              })}

              {topActiveSources.length === 0 && (
                <div className="text-center py-6 text-xs text-gray-500 font-mono">
                  No source IPs recorded yet
                </div>
              )}
            </div>
          </div>

          {/* 3. Realtime Stream Status Card */}
          <div className="glass-panel p-3.5 rounded-xl border border-white/10 text-xs text-gray-400 font-mono space-y-1.5">
            <div className="flex justify-between items-center text-gray-300 font-semibold text-[11px]">
              <span className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                Stream Engine
              </span>
              <span className="text-emerald-400">SOC READY</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span>Ingestion Buffer:</span>
              <span className="text-gray-200">{events.length} / {MAX_LIVE_EVENTS}</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span>Duplicate Filter:</span>
              <span className="text-emerald-400">ACTIVE ({seenIdsRef.current.size})</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span>Audio Alert:</span>
              <span className={soundEnabled ? 'text-cyan-300 font-bold' : 'text-gray-500'}>
                {soundEnabled ? 'UNMUTED' : 'MUTED'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LiveMonitoring;
