import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  Upload,
  FileText,
  Filter,
  Search,
  Download,
  RotateCcw,
  Check,
  Copy,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  AlertTriangle,
  ShieldAlert,
  Globe,
  Activity,
  Wifi,
  Layers,
  Lock,
  Server,
  Sliders,
  X,
  ExternalLink,
  FileCode,
  Network,
  Radio,
  Flame,
  CheckCircle2,
  Terminal,
  Clock,
  Sparkles,
  Play,
  Square,
  Pause,
  Trash2
} from 'lucide-react';
import api from '../services/api';

// ─── Interfaces ───────────────────────────────────────────────────────────────

interface HexDumpLine {
  offset: string;
  hex: string;
  ascii: string;
}

interface PacketItem {
  no: number;
  time: number;
  rel_time: number;
  time_str: string;
  source: string;
  destination: string;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: string;
  length: number;
  tcp_flags?: string;
  info: string;
  layers: Record<string, Record<string, string>>;
  hex_dump: HexDumpLine[];
  raw_bytes_len: number;
  is_suspicious?: boolean;
}

interface CaptureMetadata {
  id?: string;
  filename: string;
  file_size: number;
  total_packets: number;
  total_in_capture?: number;
  duration: number;
  duration_formatted: string;
  start_time: string;
  end_time: string;
  avg_packets_per_sec: number;
  avg_bytes_per_sec: number;
  total_bytes: number;
  analyzed_at?: string;
}

interface ProtocolDistItem {
  protocol: string;
  count: number;
  percentage: number;
}

interface ConversationItem {
  key: string;
  source: string;
  destination: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packets: number;
  bytes: number;
  duration: number;
}

interface EndpointItem {
  ip: string;
  packets: number;
  bytes: number;
  first_seen: string;
  last_seen: string;
  protocols: string[];
  is_internal: boolean;
}

interface SecurityIndicator {
  id: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  indicator: string;
  source: string;
  evidence: string;
  reason: string;
}

interface AnalysisData {
  metadata: CaptureMetadata;
  packets: PacketItem[];
  protocol_distribution: ProtocolDistItem[];
  conversations: ConversationItem[];
  endpoints: EndpointItem[];
  security_indicators: SecurityIndicator[];
}

interface CaptureHistoryItem {
  id: string;
  filename: string;
  file_size: number;
  packets: number;
  analyzed_at: string;
  duration: string;
}

interface NetworkInterface {
  id: string;
  name: string;
}

interface IpReputationData {
  ip: string;
  provider: string;
  status: string;
  threat_score?: number;
  is_malicious?: boolean;
  message?: string;
}

// ─── Protocol Color Styles ───────────────────────────────────────────────────

const PROTO_ROW_STYLE: Record<string, string> = {
  HTTP: 'hover:bg-emerald-950/20 border-l-emerald-500 text-emerald-200',
  TLS: 'hover:bg-purple-950/20 border-l-purple-500 text-purple-200',
  HTTPS: 'hover:bg-purple-950/20 border-l-purple-500 text-purple-200',
  DNS: 'hover:bg-sky-950/20 border-l-sky-500 text-sky-200',
  TCP: 'hover:bg-gray-800/30 border-l-gray-500 text-gray-300',
  UDP: 'hover:bg-amber-950/20 border-l-amber-500 text-amber-200',
  ICMP: 'hover:bg-pink-950/20 border-l-pink-500 text-pink-200',
  ARP: 'hover:bg-orange-950/20 border-l-orange-500 text-orange-200',
  SSH: 'hover:bg-indigo-950/20 border-l-indigo-500 text-indigo-200',
  OTHER: 'hover:bg-white/5 border-l-gray-600 text-gray-300',
};

const PROTO_BADGE_STYLE: Record<string, string> = {
  HTTP: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  TLS: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  HTTPS: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  DNS: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  TCP: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
  UDP: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  ICMP: 'bg-pink-500/15 text-pink-400 border-pink-500/30',
  ARP: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  SSH: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
  OTHER: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
};

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

// ─── Main Component ──────────────────────────────────────────────────────────

const PacketAnalyzer: React.FC = () => {
  // Main Data States
  const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<PacketItem | null>(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Live Packet Capturing States (#38, #39, #40)
  const [isCapturing, setIsCapturing] = useState(false);
  const [isCapturePaused, setIsCapturePaused] = useState(false);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('eth0');
  const [livePacketsCount, setLivePacketsCount] = useState(0);
  const [liveRate, setLiveRate] = useState(0);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  // Capture History & Upload Modal
  const [capturesList, setCapturesList] = useState<CaptureHistoryItem[]>([]);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  // Display Filter Bar & Filter Builder
  const [filterInput, setFilterInput] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  const [filterError, setFilterError] = useState<string | null>(null);
  const [showFilterBuilder, setShowFilterBuilder] = useState(false);
  const [builderField, setBuilderField] = useState('tcp');
  const [builderOp, setBuilderOp] = useState('==');
  const [builderVal, setBuilderVal] = useState('443');
  const [useColoring, setUseColoring] = useState(true);

  // Hex Dump View Mode: 'combined' | 'hex' | 'ascii'
  const [hexViewMode, setHexViewMode] = useState<'combined' | 'hex' | 'ascii'>('combined');

  // Multi-tab Workspace (Bottom Section)
  const [activeBottomTab, setActiveBottomTab] = useState<'details' | 'statistics' | 'conversations' | 'endpoints' | 'indicators'>('details');

  // IP Investigation Modal
  const [investigatingIp, setInvestigatingIp] = useState<string | null>(null);
  const [ipReputation, setIpReputation] = useState<IpReputationData | null>(null);
  const [ipReputationLoading, setIpReputationLoading] = useState(false);

  // Jump to packet number
  const [jumpPacketNo, setJumpPacketNo] = useState('');

  // Refs
  const fileInputRef = useRef<HTMLInputElement>(null);
  const packetTableBodyRef = useRef<HTMLDivElement>(null);
  const captureIntervalRef = useRef<any>(null);
  const captureStartTimeRef = useRef<number>(Date.now());
  const packetCounterRef = useRef<number>(0);
  const isCapturePausedRef = useRef(isCapturePaused);
  isCapturePausedRef.current = isCapturePaused;

  // ─── Initial Load (Loads Demo Capture, Interfaces & Recent Captures) ───────

  useEffect(() => {
    loadDemoCapture();
    fetchCapturesHistory();
    fetchInterfaces();

    return () => {
      if (captureIntervalRef.current) clearInterval(captureIntervalRef.current);
    };
  }, []);

  const fetchInterfaces = async () => {
    try {
      const res = await api.get('/packets/interfaces');
      if (Array.isArray(res.data) && res.data.length > 0) {
        setInterfaces(res.data);
        setSelectedInterface(res.data[0].id);
      }
    } catch {
      setInterfaces([
        { id: 'eth0', name: 'Ethernet (Primary)' },
        { id: 'lo', name: 'Loopback (127.0.0.1)' },
      ]);
    }
  };

  const loadDemoCapture = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const res = await api.get('/packets/demo');
      setAnalysisData(res.data);
      packetCounterRef.current = res.data.packets?.length || 0;
      if (res.data.packets && res.data.packets.length > 0) {
        setSelectedPacket(res.data.packets[0]);
      }
    } catch (err: any) {
      setErrorMessage(err?.response?.data?.detail || 'Failed to load initial demonstration capture.');
    } finally {
      setLoading(false);
    }
  };

  const fetchCapturesHistory = async () => {
    try {
      const res = await api.get('/packets/captures');
      if (Array.isArray(res.data)) {
        setCapturesList(res.data);
      }
    } catch {
      // Ignore
    }
  };

  // ─── Live Capture Implementation (#38, #39, #40) ───────────────────────────

  const startLiveCapture = () => {
    setIsCapturing(true);
    setIsCapturePaused(false);
    captureStartTimeRef.current = Date.now();
    let currentCount = packetCounterRef.current;
    let recentPacketTimes: number[] = [];

    // Periodic capture loop fetching real dissected packets
    captureIntervalRef.current = setInterval(async () => {
      if (isCapturePausedRef.current) return;

      currentCount += 1;
      packetCounterRef.current = currentCount;

      try {
        const baseEpoch = captureStartTimeRef.current / 1000.0;
        const res = await api.get(
          `/packets/live-packet?counter=${currentCount}&base_time=${baseEpoch}&iface=${selectedInterface}`
        );
        const newPkt: PacketItem = res.data;

        // Calculate rate
        const now = Date.now();
        recentPacketTimes.push(now);
        recentPacketTimes = recentPacketTimes.filter(t => now - t <= 3000);
        const calculatedRate = Math.round((recentPacketTimes.length / 3) * 10) / 10;
        setLiveRate(calculatedRate);

        setAnalysisData(prev => {
          if (!prev) return null;
          const updatedPackets = [...prev.packets, newPkt];

          // Recompute protocol distribution
          const protoMap: Record<string, number> = {};
          let totalBytes = prev.metadata.total_bytes + newPkt.length;
          for (const p of updatedPackets) {
            protoMap[p.protocol] = (protoMap[p.protocol] || 0) + 1;
          }
          const protoDist: ProtocolDistItem[] = Object.entries(protoMap).map(([p, cnt]) => ({
            protocol: p,
            count: cnt,
            percentage: Math.round((cnt / updatedPackets.length) * 1000) / 10,
          }));

          // Recompute duration
          const durSec = Math.max(0.1, Math.round((now - captureStartTimeRef.current) / 1000));
          const durFmt = `${Math.floor(durSec / 60).toString().padStart(2, '0')}:${(durSec % 60).toString().padStart(2, '0')}`;

          return {
            ...prev,
            packets: updatedPackets,
            protocol_distribution: protoDist,
            metadata: {
              ...prev.metadata,
              total_packets: updatedPackets.length,
              total_bytes: totalBytes,
              duration: durSec,
              duration_formatted: durFmt,
              avg_packets_per_sec: Math.round((updatedPackets.length / durSec) * 10) / 10,
            },
          };
        });

        setLivePacketsCount(prev => prev + 1);
      } catch (err) {
        console.error('Live packet fetch error:', err);
      }
    }, 1200);
  };

  const stopLiveCapture = () => {
    setIsCapturing(false);
    setIsCapturePaused(false);
    if (captureIntervalRef.current) clearInterval(captureIntervalRef.current);
    captureIntervalRef.current = null;
  };

  const togglePauseCapture = () => {
    setIsCapturePaused(prev => !prev);
  };

  const clearCurrentCapture = () => {
    stopLiveCapture();
    packetCounterRef.current = 0;
    setLivePacketsCount(0);
    setLiveRate(0);
    setSelectedPacket(null);
    setAnalysisData({
      metadata: {
        filename: `live_${selectedInterface}.pcap`,
        file_size: 0,
        total_packets: 0,
        duration: 0,
        duration_formatted: '00:00',
        start_time: new Date().toISOString(),
        end_time: new Date().toISOString(),
        avg_packets_per_sec: 0,
        avg_bytes_per_sec: 0,
        total_bytes: 0,
      },
      packets: [],
      protocol_distribution: [],
      conversations: [],
      endpoints: [],
      security_indicators: [],
    });
    setShowClearConfirm(false);
  };

  // ─── File Upload Handler (#3) ───────────────────────────────────────────────

  const handleFileUpload = async (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng' && ext !== 'cap') {
      setErrorMessage('Unsupported capture file. Please upload a valid .pcap or .pcapng file.');
      return;
    }

    stopLiveCapture();
    setUploading(true);
    setErrorMessage(null);
    setShowUploadModal(false);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await api.post('/packets/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setAnalysisData(res.data);
      packetCounterRef.current = res.data.packets?.length || 0;
      if (res.data.packets && res.data.packets.length > 0) {
        setSelectedPacket(res.data.packets[0]);
      }
      setActiveFilter('');
      setFilterInput('');
      fetchCapturesHistory();
    } catch (err: any) {
      setErrorMessage(
        err?.response?.data?.detail || 'Unable to parse capture file. It may be corrupted or in an unsupported format.'
      );
    } finally {
      setUploading(false);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // ─── Display Filter Evaluation (#7) ─────────────────────────────────────────

  const applyFilter = (filterExpr: string) => {
    const trimmed = filterExpr.trim();
    setFilterError(null);
    setActiveFilter(trimmed);
  };

  const clearFilter = () => {
    setFilterInput('');
    setActiveFilter('');
    setFilterError(null);
  };

  const handleAddBuilderFilter = () => {
    let expr = '';
    if (builderField === 'proto') {
      expr = builderVal.toLowerCase();
    } else if (builderField === 'tcp.port') {
      expr = `tcp.port ${builderOp} ${builderVal}`;
    } else if (builderField === 'udp.port') {
      expr = `udp.port ${builderOp} ${builderVal}`;
    } else if (builderField === 'ip.addr') {
      expr = `ip.addr ${builderOp} ${builderVal}`;
    } else if (builderField === 'ip.src') {
      expr = `ip.src ${builderOp} ${builderVal}`;
    } else if (builderField === 'ip.dst') {
      expr = `ip.dst ${builderOp} ${builderVal}`;
    } else {
      expr = `${builderField} ${builderOp} ${builderVal}`;
    }

    setFilterInput(expr);
    applyFilter(expr);
    setShowFilterBuilder(false);
  };

  // Filtered Packets Pipeline
  const filteredPackets = useMemo(() => {
    if (!analysisData || !analysisData.packets) return [];
    if (!activeFilter) return analysisData.packets;

    const expr = activeFilter.toLowerCase().trim();

    return analysisData.packets.filter(pkt => {
      // 1. Exact protocol name checks
      if (['tcp', 'udp', 'dns', 'http', 'tls', 'https', 'ssh', 'icmp', 'arp'].includes(expr)) {
        if (expr === 'https' || expr === 'tls') {
          return pkt.protocol === 'TLS' || pkt.protocol === 'HTTPS';
        }
        return pkt.protocol.toLowerCase() === expr;
      }

      // 2. Suspicious filter
      if (expr === 'suspicious') {
        const suspiciousSources = new Set(
          (analysisData.security_indicators || []).map(ind => ind.source)
        );
        return suspiciousSources.has(pkt.source) || pkt.info.toLowerCase().includes('rst');
      }

      // 3. Port filters: tcp.port == 443, udp.port == 53
      if (expr.includes('.port')) {
        const match = expr.match(/(tcp|udp)\.port\s*(==|!=)\s*(\d+)/);
        if (match) {
          const [, proto, op, portStr] = match;
          const targetPort = parseInt(portStr, 10);
          const portMatches = pkt.source_port === targetPort || pkt.destination_port === targetPort;
          const protoMatches = proto.toUpperCase() === pkt.protocol;
          return op === '==' ? (portMatches && (protoMatches || pkt.protocol === 'TLS' || pkt.protocol === 'HTTP')) : !portMatches;
        }
      }

      // 4. IP filters: ip.addr == ..., ip.src == ..., ip.dst == ...
      if (expr.includes('ip.')) {
        const match = expr.match(/ip\.(addr|src|dst)\s*(==|!=)\s*([\d\.\:a-f]+)/);
        if (match) {
          const [, targetField, op, targetIp] = match;
          let isMatch = false;
          if (targetField === 'addr') {
            isMatch = pkt.source.toLowerCase() === targetIp || pkt.destination.toLowerCase() === targetIp;
          } else if (targetField === 'src') {
            isMatch = pkt.source.toLowerCase() === targetIp;
          } else if (targetField === 'dst') {
            isMatch = pkt.destination.toLowerCase() === targetIp;
          }
          return op === '==' ? isMatch : !isMatch;
        }
      }

      // 5. General search fallback: matches source, destination, info, protocol, or port
      return (
        pkt.source.toLowerCase().includes(expr) ||
        pkt.destination.toLowerCase().includes(expr) ||
        pkt.protocol.toLowerCase().includes(expr) ||
        pkt.info.toLowerCase().includes(expr) ||
        String(pkt.no) === expr
      );
    });
  }, [analysisData, activeFilter]);

  // ─── Packet Navigation (#26) ───────────────────────────────────────────────

  const handleSelectIndex = (idx: number) => {
    if (!filteredPackets || filteredPackets.length === 0) return;
    const clamped = Math.max(0, Math.min(filteredPackets.length - 1, idx));
    setSelectedPacket(filteredPackets[clamped]);
  };

  const handleJumpToPacket = (e: React.FormEvent) => {
    e.preventDefault();
    const targetNo = parseInt(jumpPacketNo, 10);
    if (isNaN(targetNo)) return;
    const found = filteredPackets.find(p => p.no === targetNo);
    if (found) {
      setSelectedPacket(found);
      setJumpPacketNo('');
    } else {
      setFilterError(`Packet #${targetNo} not found in current filtered results.`);
    }
  };

  // ─── IP Threat Intelligence Lookup (#23, #24) ──────────────────────────────

  const handleInvestigateIp = async (ip: string) => {
    setInvestigatingIp(ip);
    setIpReputation(null);
    setIpReputationLoading(true);

    try {
      const res = await api.get(`/packets/ip-reputation/${ip}`);
      setIpReputation(res.data);
    } catch {
      setIpReputation({
        ip,
        provider: 'Local',
        status: 'UNAVAILABLE',
        message: 'Threat intelligence lookup failed or unavailable.',
      });
    } finally {
      setIpReputationLoading(false);
    }
  };

  // ─── Export CSV (#29) ───────────────────────────────────────────────────────

  const handleExportCsv = async () => {
    if (!filteredPackets || filteredPackets.length === 0) return;

    try {
      const exportList = filteredPackets.map(p => ({
        no: p.no,
        time_str: p.time_str,
        source: p.source,
        destination: p.destination,
        source_port: p.source_port,
        destination_port: p.destination_port,
        protocol: p.protocol,
        length: p.length,
        info: p.info,
      }));

      const res = await api.post(
        '/packets/export',
        {
          filename: `analysis_${analysisData?.metadata.filename || 'export'}.csv`,
          packets: exportList,
        },
        { responseType: 'blob' }
      );

      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `packet_analysis_${analysisData?.metadata.filename || 'export'}.csv`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (err) {
      console.error('Export CSV failed:', err);
    }
  };

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-[calc(100vh-6.5rem)] space-y-3.5">
      {/* ─── 1. Header & Capture Controls ────────────────────────────────────── */}
      <div className="glass-panel p-3.5 rounded-xl flex flex-wrap items-center justify-between gap-3 border border-white/10">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center relative">
            <Network className="w-5 h-5 text-cyan-400" />
            {isCapturing && !isCapturePaused && (
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
            )}
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-base font-black tracking-wider uppercase text-gray-900 dark:text-white">
                Packet Analyzer
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
                WIRESHARK DISSECTOR
              </span>

              {/* Live Capturing Indicator (#38) */}
              {isCapturing && (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span>
                  {isCapturePaused ? 'CAPTURE PAUSED' : 'CAPTURE ACTIVE'}
                </span>
              )}
            </div>

            {analysisData?.metadata ? (
              <p className="text-xs text-gray-400 font-mono mt-0.5 flex items-center space-x-3">
                <span className="font-bold text-gray-200">{analysisData.metadata.filename}</span>
                <span>•</span>
                <span>{analysisData.metadata.total_packets.toLocaleString()} packets</span>
                <span>•</span>
                <span>{formatBytes(analysisData.metadata.file_size || analysisData.metadata.total_bytes)}</span>
                <span>•</span>
                <span>Duration: {analysisData.metadata.duration_formatted}</span>
                {isCapturing && (
                  <>
                    <span>•</span>
                    <span className="text-emerald-400 font-bold">{liveRate} pkts/sec</span>
                  </>
                )}
              </p>
            ) : (
              <p className="text-xs text-gray-500 font-mono mt-0.5">No capture loaded</p>
            )}
          </div>
        </div>

        {/* Action Controls & Live Toolbar (#38, #39, #40) */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Network Interface Dropdown (#39) */}
          <div className="flex items-center space-x-1.5 bg-black/20 dark:bg-[#1a1b26] px-2 py-1 rounded-lg border border-gray-700/60">
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            <select
              value={selectedInterface}
              onChange={e => setSelectedInterface(e.target.value)}
              disabled={isCapturing}
              className="bg-transparent text-gray-200 text-xs font-mono focus:outline-none cursor-pointer"
            >
              {interfaces.map(iface => (
                <option key={iface.id} value={iface.id} className="bg-[#1a1b26] text-gray-200">
                  {iface.name}
                </option>
              ))}
            </select>
          </div>

          {/* Start / Stop Capture Button (#38, #40) */}
          {isCapturing ? (
            <button
              onClick={stopLiveCapture}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white transition shadow-sm animate-pulse"
            >
              <Square className="w-3.5 h-3.5" />
              <span>Stop Capture</span>
            </button>
          ) : (
            <button
              onClick={startLiveCapture}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition shadow-sm"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Start Capture</span>
            </button>
          )}

          {/* Pause / Resume Button while capturing (#38) */}
          {isCapturing && (
            <button
              onClick={togglePauseCapture}
              className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition ${
                isCapturePaused
                  ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                  : 'bg-white/5 border-gray-700 text-gray-300 hover:bg-white/10'
              }`}
            >
              {isCapturePaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
              <span>{isCapturePaused ? 'Resume' : 'Pause'}</span>
            </button>
          )}

          {/* Clear Capture Button (#40) */}
          <button
            onClick={() => setShowClearConfirm(true)}
            disabled={!analysisData?.packets?.length}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-white/5 hover:bg-white/10 text-gray-400 hover:text-rose-400 border border-white/10 transition disabled:opacity-30"
            title="Clear current capture"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear</span>
          </button>

          {/* Recent Captures Dropdown (#28) */}
          {capturesList.length > 0 && (
            <select
              onChange={async e => {
                const targetId = e.target.value;
                if (!targetId) return;
                stopLiveCapture();
                setLoading(true);
                try {
                  const res = await api.get(`/packets/captures/${targetId}`);
                  setAnalysisData(res.data);
                  packetCounterRef.current = res.data.packets?.length || 0;
                  if (res.data.packets?.length > 0) setSelectedPacket(res.data.packets[0]);
                } catch {
                  // Fallback
                } finally {
                  setLoading(false);
                }
              }}
              className="px-2.5 py-1.5 rounded-lg bg-black/20 dark:bg-[#1a1b26] border border-gray-700/60 text-gray-300 text-xs font-mono focus:outline-none"
            >
              <option value="">Recent Captures...</option>
              {capturesList.map(c => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.packets} pkts)
                </option>
              ))}
            </select>
          )}

          {/* Load Sample PCAP */}
          <button
            onClick={() => { stopLiveCapture(); loadDemoCapture(); }}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 transition"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Sample PCAP</span>
          </button>

          {/* Upload Button (#3) */}
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-sm"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload PCAP</span>
          </button>

          {/* Export CSV (#29) */}
          <button
            onClick={handleExportCsv}
            disabled={!filteredPackets.length}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 transition disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* ─── Clear Confirmation Modal (#40) ──────────────────────────────────── */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-sm p-5 rounded-2xl border border-white/20 space-y-3 font-mono text-xs shadow-2xl">
            <div className="flex items-center space-x-2 text-rose-400">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <h3 className="font-bold text-sm text-gray-100">Clear Current Capture?</h3>
            </div>
            <p className="text-gray-400">
              This will clear the currently active packet capture workspace. Any unsaved live data will be reset.
            </p>
            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-gray-800">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-gray-300 font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={clearCurrentCapture}
                className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold"
              >
                Confirm Clear
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Error Notification Banner ───────────────────────────────────────── */}
      {errorMessage && (
        <div className="flex items-center justify-between px-4 py-2.5 rounded-xl bg-rose-950/70 border border-rose-500/40 text-rose-200 text-xs">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button onClick={() => setErrorMessage(null)} className="p-1 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ─── 2. Display Filter Bar & Quick Filters (#7, #8) ──────────────────── */}
      <div className="glass-panel p-2.5 rounded-xl flex flex-col space-y-2 border border-white/10">
        <div className="flex items-center gap-2">
          {/* Wireshark-Style Filter Input Bar */}
          <div className="relative flex-1">
            <Filter className="w-3.5 h-3.5 absolute left-3 top-2.5 text-cyan-400" />
            <input
              type="text"
              value={filterInput}
              onChange={e => setFilterInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applyFilter(filterInput)}
              placeholder='Display filter: tcp, udp, dns, tls, http, icmp, tcp.port == 443, ip.addr == 192.168.1.105, suspicious'
              className="w-full pl-9 pr-20 py-1.5 rounded-lg bg-black/30 dark:bg-black/40 border border-gray-700/60 text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500 placeholder:text-gray-600 transition"
            />
            <div className="absolute right-1.5 top-1 flex items-center space-x-1">
              <button
                onClick={() => applyFilter(filterInput)}
                className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-[11px] transition"
              >
                Apply
              </button>
              {activeFilter && (
                <button
                  onClick={clearFilter}
                  className="px-2 py-1 rounded bg-white/10 hover:bg-white/20 text-gray-300 text-[11px] transition"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Filter Builder Toggle (#8) */}
          <button
            onClick={() => setShowFilterBuilder(!showFilterBuilder)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-semibold flex items-center space-x-1.5 transition ${
              showFilterBuilder
                ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                : 'bg-white/5 border-gray-700 text-gray-300 hover:bg-white/10'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Filter Builder</span>
          </button>

          {/* Coloring Toggle (#6) */}
          <button
            onClick={() => setUseColoring(!useColoring)}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono transition ${
              useColoring
                ? 'bg-purple-500/20 border-purple-500/40 text-purple-300'
                : 'bg-white/5 border-gray-700 text-gray-500'
            }`}
            title="Toggle protocol row coloring"
          >
            Coloring {useColoring ? 'ON' : 'OFF'}
          </button>
        </div>

        {/* Filter Builder Drawer (#8) */}
        {showFilterBuilder && (
          <div className="p-3 rounded-lg bg-black/20 dark:bg-black/40 border border-white/5 flex flex-wrap items-center gap-2.5 text-xs font-mono animate-in slide-in-from-top-1">
            <span className="text-gray-400 font-bold">Field:</span>
            <select
              value={builderField}
              onChange={e => setBuilderField(e.target.value)}
              className="px-2 py-1 rounded bg-black/40 border border-gray-700 text-gray-200 text-xs"
            >
              <option value="proto">Protocol</option>
              <option value="tcp.port">TCP Port</option>
              <option value="udp.port">UDP Port</option>
              <option value="ip.addr">IP Address (Any)</option>
              <option value="ip.src">Source IP</option>
              <option value="ip.dst">Destination IP</option>
            </select>

            <span className="text-gray-400 font-bold">Operator:</span>
            <select
              value={builderOp}
              onChange={e => setBuilderOp(e.target.value)}
              className="px-2 py-1 rounded bg-black/40 border border-gray-700 text-gray-200 text-xs"
            >
              <option value="==">== (Equals)</option>
              <option value="!=">!= (Not Equals)</option>
            </select>

            <span className="text-gray-400 font-bold">Value:</span>
            <input
              type="text"
              value={builderVal}
              onChange={e => setBuilderVal(e.target.value)}
              placeholder="e.g. 443, 80, 192.168.1.105"
              className="px-2.5 py-1 rounded bg-black/40 border border-gray-700 text-cyan-300 text-xs w-44"
            />

            <button
              onClick={handleAddBuilderFilter}
              className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs"
            >
              Apply Filter
            </button>
          </div>
        )}

        {/* Quick Filter Chips & Match Count */}
        <div className="flex flex-wrap items-center justify-between text-xs font-mono pt-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-gray-500 text-[11px] mr-1">Quick:</span>
            {['All', 'TCP', 'UDP', 'DNS', 'HTTP', 'TLS', 'SSH', 'ICMP', 'ARP', 'Suspicious'].map(qf => (
              <button
                key={qf}
                onClick={() => {
                  if (qf === 'All') clearFilter();
                  else {
                    setFilterInput(qf.toLowerCase());
                    applyFilter(qf.toLowerCase());
                  }
                }}
                className={`px-2 py-0.5 rounded text-[11px] transition ${
                  (qf === 'All' && !activeFilter) || activeFilter.toLowerCase() === qf.toLowerCase()
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                    : 'bg-white/5 hover:bg-white/10 text-gray-400 border border-white/5'
                }`}
              >
                {qf}
              </button>
            ))}
          </div>

          <div className="text-gray-400 text-xs">
            Showing{' '}
            <span className="font-bold text-cyan-400">{filteredPackets.length}</span> of{' '}
            <span>{analysisData?.packets?.length || 0}</span> packets
          </div>
        </div>
      </div>

      {/* ─── 3. Wireshark Three-Panel Central Workspace (#11) ───────────────── */}
      <div className="flex-1 grid grid-rows-12 gap-3 min-h-0">
        {/* ─── Panel 1: Packet List Table (Top half - 6 rows) ────────────────── */}
        <div className="row-span-6 glass-panel rounded-xl overflow-hidden flex flex-col border border-white/10 min-h-0">
          {/* Table Header */}
          <div className="bg-black/20 dark:bg-[#161b22] border-b border-gray-800 text-[11px] font-bold text-gray-400 grid grid-cols-12 px-3 py-2 shrink-0 select-none">
            <div className="col-span-1">No.</div>
            <div className="col-span-1">Time (s)</div>
            <div className="col-span-2">Source</div>
            <div className="col-span-2">Destination</div>
            <div className="col-span-1">Protocol</div>
            <div className="col-span-1">Length</div>
            <div className="col-span-4">Info</div>
          </div>

          {/* Table Body (Virtualized scroll) */}
          <div ref={packetTableBodyRef} className="flex-1 overflow-y-auto divide-y divide-gray-800/40 text-xs font-mono">
            {filteredPackets.map((pkt, idx) => {
              const isSelected = selectedPacket?.no === pkt.no;
              const rowStyle = useColoring ? PROTO_ROW_STYLE[pkt.protocol] || PROTO_ROW_STYLE.OTHER : 'hover:bg-white/5';
              const badgeStyle = PROTO_BADGE_STYLE[pkt.protocol] || PROTO_BADGE_STYLE.OTHER;

              return (
                <div
                  key={pkt.no}
                  onClick={() => setSelectedPacket(pkt)}
                  className={`grid grid-cols-12 px-3 py-1.5 cursor-pointer transition-colors border-l-4 select-none ${
                    isSelected
                      ? 'bg-cyan-900/30 text-cyan-200 border-l-cyan-400 ring-1 ring-cyan-500/30 font-semibold'
                      : `${rowStyle}`
                  }`}
                >
                  <div className="col-span-1 text-gray-500 flex items-center space-x-1">
                    <span>{pkt.no}</span>
                    {pkt.is_suspicious && (
                      <span title="Suspicious packet indicator">
                        <AlertTriangle className="w-3 h-3 text-rose-400" />
                      </span>
                    )}
                  </div>
                  <div className="col-span-1 text-gray-400">{pkt.rel_time.toFixed(4)}</div>
                  <div className="col-span-2 truncate text-gray-200 hover:text-cyan-300" onClick={e => { e.stopPropagation(); handleInvestigateIp(pkt.source); }}>
                    {pkt.source}
                  </div>
                  <div className="col-span-2 truncate text-gray-200 hover:text-cyan-300" onClick={e => { e.stopPropagation(); handleInvestigateIp(pkt.destination); }}>
                    {pkt.destination}
                  </div>
                  <div className="col-span-1">
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${badgeStyle}`}>
                      {pkt.protocol}
                    </span>
                  </div>
                  <div className="col-span-1 text-gray-400">{pkt.length}</div>
                  <div className="col-span-4 truncate text-gray-300">{pkt.info}</div>
                </div>
              );
            })}

            {filteredPackets.length === 0 && (
              <div className="h-40 flex flex-col items-center justify-center text-center text-gray-500 text-xs">
                <FileCode className="w-8 h-8 text-gray-600 mb-2" />
                <p>No packets match current filter expression.</p>
                <button onClick={clearFilter} className="mt-2 text-cyan-400 underline">
                  Clear Filter
                </button>
              </div>
            )}
          </div>

          {/* Packet Table Footer Navigation (#26) */}
          <div className="px-3 py-1.5 bg-black/20 dark:bg-[#161b22] border-t border-gray-800 flex items-center justify-between text-xs text-gray-400 font-mono">
            <div className="flex items-center space-x-1.5">
              <button
                onClick={() => handleSelectIndex(0)}
                className="p-1 rounded hover:bg-white/10"
                title="First packet"
              >
                <ChevronsLeft className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => {
                  const currIdx = filteredPackets.findIndex(p => p.no === selectedPacket?.no);
                  handleSelectIndex(currIdx - 1);
                }}
                className="p-1 rounded hover:bg-white/10"
                title="Previous packet"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="text-gray-300 font-bold px-1">
                {selectedPacket ? `Packet #${selectedPacket.no}` : 'None'}
              </span>
              <button
                onClick={() => {
                  const currIdx = filteredPackets.findIndex(p => p.no === selectedPacket?.no);
                  handleSelectIndex(currIdx + 1);
                }}
                className="p-1 rounded hover:bg-white/10"
                title="Next packet"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => handleSelectIndex(filteredPackets.length - 1)}
                className="p-1 rounded hover:bg-white/10"
                title="Last packet"
              >
                <ChevronsRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Jump to packet form */}
            <form onSubmit={handleJumpToPacket} className="flex items-center space-x-1.5">
              <span className="text-[11px] text-gray-500">Go to:</span>
              <input
                type="number"
                value={jumpPacketNo}
                onChange={e => setJumpPacketNo(e.target.value)}
                placeholder="#"
                className="w-16 px-1.5 py-0.5 rounded bg-black/30 border border-gray-700 text-xs font-mono text-center text-cyan-300"
              />
            </form>
          </div>
        </div>

        {/* ─── Bottom Panels (Details, Bytes, Analytics Tabs - 6 rows) ───────── */}
        <div className="row-span-6 flex flex-col min-h-0 glass-panel rounded-xl overflow-hidden border border-white/10">
          {/* Workspace Tabs Header */}
          <div className="px-3 pt-2 bg-black/20 dark:bg-[#161b22] border-b border-gray-800 flex items-center justify-between">
            <div className="flex items-center space-x-1 text-xs">
              <button
                onClick={() => setActiveBottomTab('details')}
                className={`px-3 py-1.5 rounded-t-lg font-bold transition flex items-center space-x-1.5 ${
                  activeBottomTab === 'details'
                    ? 'bg-cyan-500/10 text-cyan-300 border-b-2 border-cyan-400 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Packet Details & Bytes</span>
              </button>

              <button
                onClick={() => setActiveBottomTab('statistics')}
                className={`px-3 py-1.5 rounded-t-lg font-bold transition flex items-center space-x-1.5 ${
                  activeBottomTab === 'statistics'
                    ? 'bg-cyan-500/10 text-cyan-300 border-b-2 border-cyan-400 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Statistics</span>
              </button>

              <button
                onClick={() => setActiveBottomTab('conversations')}
                className={`px-3 py-1.5 rounded-t-lg font-bold transition flex items-center space-x-1.5 ${
                  activeBottomTab === 'conversations'
                    ? 'bg-cyan-500/10 text-cyan-300 border-b-2 border-cyan-400 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Radio className="w-3.5 h-3.5" />
                <span>Conversations ({analysisData?.conversations?.length || 0})</span>
              </button>

              <button
                onClick={() => setActiveBottomTab('endpoints')}
                className={`px-3 py-1.5 rounded-t-lg font-bold transition flex items-center space-x-1.5 ${
                  activeBottomTab === 'endpoints'
                    ? 'bg-cyan-500/10 text-cyan-300 border-b-2 border-cyan-400 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Endpoints ({analysisData?.endpoints?.length || 0})</span>
              </button>

              <button
                onClick={() => setActiveBottomTab('indicators')}
                className={`px-3 py-1.5 rounded-t-lg font-bold transition flex items-center space-x-1.5 ${
                  activeBottomTab === 'indicators'
                    ? 'bg-rose-500/10 text-rose-300 border-b-2 border-rose-400 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                <span>Security Indicators ({analysisData?.security_indicators?.length || 0})</span>
              </button>
            </div>

            {selectedPacket && activeBottomTab === 'details' && (
              <span className="text-[11px] font-mono text-gray-400 pb-1.5">
                Packet #{selectedPacket.no} • {selectedPacket.protocol} • {selectedPacket.length} bytes
              </span>
            )}
          </div>

          {/* Workspace Tab Content */}
          <div className="flex-1 overflow-hidden min-h-0 bg-[#0d1117]">
            {/* ─── TAB 1: Split Details & Hex Dump (#9, #10) ──────────────────── */}
            {activeBottomTab === 'details' && (
              <div className="h-full flex divide-x divide-gray-800">
                {/* Protocol Tree (#9) */}
                <div className="flex-1 overflow-y-auto p-3 divide-y divide-gray-800/40 text-xs font-mono">
                  {selectedPacket ? (
                    Object.entries(selectedPacket.layers || {}).map(([layerName, layerData]) => (
                      <div key={layerName} className="py-1.5">
                        <div className="font-bold text-cyan-400 uppercase tracking-wide flex items-center space-x-1.5 mb-1">
                          <ChevronDown className="w-3.5 h-3.5 text-cyan-500" />
                          <span>{layerName.toUpperCase()} LAYER</span>
                        </div>
                        <div className="pl-5 space-y-0.5">
                          {Object.entries(layerData).map(([k, v]) => (
                            <div key={k} className="flex py-0.5 hover:bg-white/5 px-1.5 rounded">
                              <span className="text-gray-500 w-44 shrink-0">{k}:</span>
                              <span className="text-gray-200 select-all">{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="h-full flex items-center justify-center text-gray-500">
                      Select a packet to inspect protocol layers
                    </div>
                  )}
                </div>

                {/* Raw Hex & ASCII Bytes (#10) */}
                <div className="w-[450px] shrink-0 overflow-y-auto p-3 text-xs font-mono bg-black/40">
                  <div className="flex items-center justify-between mb-2 pb-1 border-b border-gray-800 text-[11px] text-gray-400">
                    <span className="font-bold">PACKET BYTES (HEX / ASCII)</span>
                    <div className="flex items-center space-x-1">
                      <button
                        onClick={() => setHexViewMode('combined')}
                        className={`px-1.5 py-0.5 rounded ${hexViewMode === 'combined' ? 'bg-cyan-500/20 text-cyan-300' : 'text-gray-500'}`}
                      >
                        All
                      </button>
                      <button
                        onClick={() => setHexViewMode('hex')}
                        className={`px-1.5 py-0.5 rounded ${hexViewMode === 'hex' ? 'bg-cyan-500/20 text-cyan-300' : 'text-gray-500'}`}
                      >
                        Hex
                      </button>
                      <button
                        onClick={() => setHexViewMode('ascii')}
                        className={`px-1.5 py-0.5 rounded ${hexViewMode === 'ascii' ? 'bg-cyan-500/20 text-cyan-300' : 'text-gray-500'}`}
                      >
                        ASCII
                      </button>
                    </div>
                  </div>

                  {selectedPacket?.hex_dump ? (
                    <div className="space-y-0.5 leading-relaxed select-all">
                      {selectedPacket.hex_dump.map((line, lidx) => (
                        <div key={lidx} className="flex hover:bg-white/5 px-1 rounded">
                          <span className="text-cyan-600 w-12 shrink-0 select-none">{line.offset}</span>
                          {(hexViewMode === 'combined' || hexViewMode === 'hex') && (
                            <span className="text-gray-300 flex-1">{line.hex}</span>
                          )}
                          {(hexViewMode === 'combined' || hexViewMode === 'ascii') && (
                            <span className="text-emerald-400 w-24 shrink-0 text-right">{line.ascii}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-gray-500 text-center py-10">No packet bytes to display</div>
                  )}
                </div>
              </div>
            )}

            {/* ─── TAB 2: Statistics & Distribution (#13, #14) ────────────────── */}
            {activeBottomTab === 'statistics' && analysisData && (
              <div className="h-full overflow-y-auto p-4 space-y-4 text-xs font-mono">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="glass-card p-3 rounded-xl border border-white/10">
                    <span className="text-gray-400 text-[10px] uppercase block">Total Packets</span>
                    <span className="text-xl font-bold text-cyan-400">{analysisData.metadata.total_packets}</span>
                  </div>
                  <div className="glass-card p-3 rounded-xl border border-white/10">
                    <span className="text-gray-400 text-[10px] uppercase block">Total Volume</span>
                    <span className="text-xl font-bold text-gray-200">{formatBytes(analysisData.metadata.total_bytes)}</span>
                  </div>
                  <div className="glass-card p-3 rounded-xl border border-white/10">
                    <span className="text-gray-400 text-[10px] uppercase block">Average Rate</span>
                    <span className="text-xl font-bold text-emerald-400">{analysisData.metadata.avg_packets_per_sec} pkts/s</span>
                  </div>
                  <div className="glass-card p-3 rounded-xl border border-white/10">
                    <span className="text-gray-400 text-[10px] uppercase block">Throughput</span>
                    <span className="text-xl font-bold text-purple-400">{formatBytes(analysisData.metadata.avg_bytes_per_sec)}/s</span>
                  </div>
                </div>

                {/* Protocol Distribution Bars (#14) */}
                <div className="glass-card p-4 rounded-xl border border-white/10 space-y-2.5">
                  <span className="text-xs font-bold text-gray-300 uppercase block">Protocol Breakdown</span>
                  <div className="space-y-2">
                    {analysisData.protocol_distribution.map(pd => (
                      <div
                        key={pd.protocol}
                        onClick={() => {
                          setFilterInput(pd.protocol.toLowerCase());
                          applyFilter(pd.protocol.toLowerCase());
                        }}
                        className="cursor-pointer group"
                      >
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-gray-300 font-bold group-hover:text-cyan-300">{pd.protocol}</span>
                          <span className="text-gray-400">{pd.count} pkts ({pd.percentage}%)</span>
                        </div>
                        <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                          <div
                            style={{ width: `${pd.percentage}%` }}
                            className="bg-cyan-500 h-full rounded-full transition-all duration-300 group-hover:bg-cyan-400"
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ─── TAB 3: Conversations (#16) ─────────────────────────────────── */}
            {activeBottomTab === 'conversations' && analysisData && (
              <div className="h-full overflow-y-auto p-3 text-xs font-mono">
                <table className="w-full text-left">
                  <thead className="sticky top-0 bg-[#161b22] text-gray-400 border-b border-gray-800 text-[11px]">
                    <tr>
                      <th className="py-2 px-3">Session</th>
                      <th className="py-2 px-3">Protocol</th>
                      <th className="py-2 px-3">Packets</th>
                      <th className="py-2 px-3">Bytes</th>
                      <th className="py-2 px-3">Duration</th>
                      <th className="py-2 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/40">
                    {analysisData.conversations.map(conv => (
                      <tr key={conv.key} className="hover:bg-white/5 transition">
                        <td className="py-2 px-3 text-gray-200">
                          {conv.source}:{conv.source_port} <span className="text-cyan-500">&harr;</span> {conv.destination}:{conv.destination_port}
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${PROTO_BADGE_STYLE[conv.protocol] || PROTO_BADGE_STYLE.OTHER}`}>
                            {conv.protocol}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-gray-300">{conv.packets}</td>
                        <td className="py-2 px-3 text-gray-400">{formatBytes(conv.bytes)}</td>
                        <td className="py-2 px-3 text-gray-400">{conv.duration}s</td>
                        <td className="py-2 px-3 text-right">
                          <button
                            onClick={() => {
                              const f = `ip.addr == ${conv.source}`;
                              setFilterInput(f);
                              applyFilter(f);
                              setActiveBottomTab('details');
                            }}
                            className="text-cyan-400 hover:underline text-[11px]"
                          >
                            Filter Session
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ─── TAB 4: Endpoints (#17) ─────────────────────────────────────── */}
            {activeBottomTab === 'endpoints' && analysisData && (
              <div className="h-full overflow-y-auto p-3 text-xs font-mono">
                <table className="w-full text-left">
                  <thead className="sticky top-0 bg-[#161b22] text-gray-400 border-b border-gray-800 text-[11px]">
                    <tr>
                      <th className="py-2 px-3">IP Address</th>
                      <th className="py-2 px-3">Scope</th>
                      <th className="py-2 px-3">Packets</th>
                      <th className="py-2 px-3">Volume</th>
                      <th className="py-2 px-3">Protocols</th>
                      <th className="py-2 px-3 text-right">Triage</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/40">
                    {analysisData.endpoints.map(ep => (
                      <tr key={ep.ip} className="hover:bg-white/5 transition">
                        <td
                          className="py-2 px-3 text-cyan-300 font-bold hover:underline cursor-pointer"
                          onClick={() => handleInvestigateIp(ep.ip)}
                        >
                          {ep.ip}
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${ep.is_internal ? 'bg-sky-500/20 text-sky-300' : 'bg-rose-500/20 text-rose-300'}`}>
                            {ep.is_internal ? 'INTERNAL' : 'EXTERNAL'}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-gray-300">{ep.packets}</td>
                        <td className="py-2 px-3 text-gray-400">{formatBytes(ep.bytes)}</td>
                        <td className="py-2 px-3 text-gray-400">{ep.protocols.join(', ')}</td>
                        <td className="py-2 px-3 text-right space-x-2">
                          <button
                            onClick={() => handleInvestigateIp(ep.ip)}
                            className="text-purple-400 hover:underline text-[11px]"
                          >
                            Threat Intel
                          </button>
                          <button
                            onClick={() => {
                              const f = `ip.addr == ${ep.ip}`;
                              setFilterInput(f);
                              applyFilter(f);
                              setActiveBottomTab('details');
                            }}
                            className="text-cyan-400 hover:underline text-[11px]"
                          >
                            Filter
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ─── TAB 5: Security Indicators (#22) ──────────────────────────── */}
            {activeBottomTab === 'indicators' && analysisData && (
              <div className="h-full overflow-y-auto p-4 space-y-3 text-xs font-mono">
                {analysisData.security_indicators.map(ind => (
                  <div
                    key={ind.id}
                    className="glass-card p-3.5 rounded-xl border border-rose-500/30 bg-rose-950/20 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/30 text-rose-300 border border-rose-500/40">
                          {ind.severity}
                        </span>
                        <h4 className="font-bold text-gray-200 text-sm tracking-wide">{ind.indicator}</h4>
                      </div>
                      <button
                        onClick={() => {
                          const f = `ip.addr == ${ind.source}`;
                          setFilterInput(f);
                          applyFilter(f);
                          setActiveBottomTab('details');
                        }}
                        className="px-2.5 py-1 rounded bg-rose-600/40 hover:bg-rose-600/60 text-rose-200 text-xs font-semibold"
                      >
                        Filter Related Packets
                      </button>
                    </div>

                    <div className="text-gray-300">
                      <span className="text-gray-500">Source: </span>
                      <span
                        className="text-cyan-300 font-bold hover:underline cursor-pointer"
                        onClick={() => handleInvestigateIp(ind.source)}
                      >
                        {ind.source}
                      </span>
                    </div>

                    <div className="p-2.5 rounded bg-black/40 border border-gray-800 text-gray-300">
                      <span className="text-gray-500 block uppercase text-[10px] mb-1">Evidence</span>
                      <p>{ind.evidence}</p>
                    </div>

                    <p className="text-gray-400 text-[11px] italic">{ind.reason}</p>
                  </div>
                ))}

                {analysisData.security_indicators.length === 0 && (
                  <div className="h-40 flex flex-col items-center justify-center text-center text-gray-500 text-xs">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500 mb-2" />
                    <p>No automated security indicators detected in this packet capture.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ─── IP Investigation Modal (#23, #24) ───────────────────────────────── */}
      {investigatingIp && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="glass-panel w-full max-w-lg p-5 rounded-2xl border border-white/20 space-y-4 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-2.5">
                <Globe className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-sm text-gray-100">IP Intelligence Triage</h3>
              </div>
              <button onClick={() => setInvestigatingIp(null)} className="p-1 hover:text-white text-gray-400">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-gray-500 text-[10px] block uppercase">Target IP Address</span>
                <span className="text-base font-bold text-cyan-300">{investigatingIp}</span>
              </div>

              <div className="p-3 rounded-lg bg-black/40 border border-gray-800 space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-400">Classification:</span>
                  <span className="font-bold text-gray-200">
                    {investigatingIp.startsWith('10.') || investigatingIp.startsWith('192.168.') || investigatingIp.startsWith('172.') ? 'RFC 1918 Private Network' : 'Public Routable IP'}
                  </span>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Threat Intelligence Status:</span>
                  {ipReputationLoading ? (
                    <span className="text-cyan-400 animate-pulse">Querying Threat Intel...</span>
                  ) : ipReputation ? (
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      ipReputation.status === 'SUCCESS' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300'
                    }`}>
                      {ipReputation.status}
                    </span>
                  ) : (
                    <span className="text-gray-500">Not checked</span>
                  )}
                </div>

                {ipReputation?.threat_score !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-gray-400">Threat Score:</span>
                    <span className="font-bold text-rose-400">{ipReputation.threat_score}/100</span>
                  </div>
                )}

                {ipReputation?.provider && (
                  <div className="flex justify-between">
                    <span className="text-gray-400">Intelligence Provider:</span>
                    <span className="text-gray-300">{ipReputation.provider}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-3 border-t border-gray-800">
              <button
                onClick={() => {
                  const f = `ip.addr == ${investigatingIp}`;
                  setFilterInput(f);
                  applyFilter(f);
                  setInvestigatingIp(null);
                }}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
              >
                Filter Capture by this IP
              </button>
              <button
                onClick={() => setInvestigatingIp(null)}
                className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-gray-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Upload PCAP Modal (#3) ─────────────────────────────────────────── */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="glass-panel w-full max-w-lg p-6 rounded-2xl border border-white/20 space-y-4 font-mono shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-2.5">
                <Upload className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-sm text-gray-100 uppercase tracking-wider">Upload Packet Capture</h3>
              </div>
              <button onClick={() => setShowUploadModal(false)} className="p-1 hover:text-white text-gray-400">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`p-8 rounded-xl border-2 border-dashed transition-all flex flex-col items-center justify-center text-center cursor-pointer ${
                dragActive
                  ? 'border-cyan-400 bg-cyan-500/10'
                  : 'border-gray-700 hover:border-gray-500 bg-black/20'
              }`}
            >
              <Upload className="w-10 h-10 text-cyan-400 mb-3" />
              <h4 className="font-bold text-gray-200 text-sm mb-1">Drag & Drop PCAP / PCAPNG File</h4>
              <p className="text-xs text-gray-500 mb-4">Supports .pcap, .pcapng, and .cap files (up to 50MB)</p>
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-sm"
              >
                Browse File
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={e => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
                className="hidden"
              />
            </div>

            <div className="flex justify-between items-center text-[11px] text-gray-500 pt-2 border-t border-gray-800">
              <span>Secure sandbox parsing via Scapy</span>
              <button
                onClick={() => setShowUploadModal(false)}
                className="px-3 py-1 rounded bg-white/10 hover:bg-white/20 text-gray-300"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PacketAnalyzer;
