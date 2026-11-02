import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  FileText,
  Settings,
  Shield,
  LogOut,
  Radio,
  Wifi,
  Sun,
  Moon,
  Bell,
  ChevronLeft,
  ChevronRight,
  Search,
  User,
  Download,
  AlertTriangle,
  X,
  CheckCircle,
} from 'lucide-react';
import api, { authService } from '../services/api';
import { useRealtime } from '../hooks/useRealtime';
import { useState, useEffect, useMemo, useRef } from 'react';

const ROUTE_TITLES: Record<string, { title: string; section: string; desc: string }> = {
  '/dashboard': { section: 'Overview', title: 'Security Operations Dashboard', desc: 'Unified telemetry, threat intelligence, and KPI monitoring' },
  '/live-monitoring': { section: 'Real-Time', title: 'Live Security Stream', desc: 'Continuous log streaming and anomaly detection console' },
  '/logs': { section: 'Telemetry', title: 'Event Explorer', desc: 'Search, filter, and inspect normalized security events' },
  '/alerts': { section: 'Investigation', title: 'Threat Alerts & AI', desc: 'Active security detections, triaging, and AI explanations' },
  '/incidents': { section: 'Response', title: 'Incident Response', desc: 'Escalated cases, audit trails, and forensic reports' },
  '/packet-analyzer': { section: 'Network Forensics', title: 'Deep Packet Analyzer', desc: 'PCAP dissection, live interface capture, and protocol inspection' },
  '/admin': { section: 'System', title: 'Administration & Config', desc: 'Ingestion pipelines, parsing rules, and platform settings' },
};

const Layout = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { status, lastEvent } = useRealtime();

  // Sidebar collapse state
  const [collapsed, setCollapsed] = useState(() => {
    return localStorage.getItem('loganalyzer_sidebar_collapsed') === 'true';
  });

  // Dark/Day mode state
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem('loganalyzer_theme');
    if (saved) return saved === 'dark';
    return true; // Default to Dark SOC mode
  });

  // Notifications popover state
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const notifRef = useRef<HTMLDivElement>(null);

  // Active toast alert
  const [toast, setToast] = useState<any>(null);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [currentUser, setCurrentUser] = useState<any>(null);

  // Apply theme to document
  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('loganalyzer_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('loganalyzer_theme', 'day');
    }
  }, [isDark]);

  // Fetch current user details
  useEffect(() => {
    authService.getCurrentUser()
      .then(user => setCurrentUser(user))
      .catch(() => {
        // Fallback demo user
        setCurrentUser({ username: 'SecOps Analyst', role: 'SECURITY_ADMIN' });
      });
  }, []);

  // Listen for real-time events for notifications & toast
  useEffect(() => {
    if (lastEvent) {
      if (lastEvent.type === 'NEW_ALERT') {
        const alertData = lastEvent.data;
        setToast(alertData);
        setNotifications(prev => [
          {
            id: Date.now(),
            title: alertData.title || 'Security Alert Detected',
            severity: alertData.severity || 'HIGH',
            time: new Date().toLocaleTimeString(),
            source_ip: alertData.source_ip,
          },
          ...prev.slice(0, 19),
        ]);
        setUnreadCount(c => c + 1);

        const timer = setTimeout(() => setToast(null), 7000);
        return () => clearTimeout(timer);
      }
    }
  }, [lastEvent]);

  // Close notifications dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const toggleSidebar = () => {
    setCollapsed(prev => {
      const next = !prev;
      localStorage.setItem('loganalyzer_sidebar_collapsed', String(next));
      return next;
    });
  };

  const handleLogout = () => {
    authService.logout();
    navigate('/login');
  };

  const handleExportCSV = async () => {
    setExportingCsv(true);
    try {
      const response = await api.get('/reports/events/csv', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `security_events_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (e) {
      console.error('Failed to export CSV:', e);
      alert('Failed to export CSV. Ensure you have proper permissions.');
    } finally {
      setExportingCsv(false);
    }
  };

  const currentMeta = useMemo(() => {
    const match = Object.keys(ROUTE_TITLES).find(k => location.pathname.startsWith(k));
    return match ? ROUTE_TITLES[match] : { section: 'SOC', title: 'Security Console', desc: 'Secure enterprise telemetry' };
  }, [location.pathname]);

  const navItemClass = (path: string) => {
    const active = location.pathname.startsWith(path);
    return `group flex items-center ${collapsed ? 'justify-center px-0 py-3' : 'px-4 py-2.5'} rounded-xl text-sm font-medium transition-all duration-200 relative ${
      active
        ? 'bg-blue-600/10 text-blue-600 dark:bg-blue-500/15 dark:text-blue-400 font-semibold shadow-sm border border-blue-500/20'
        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-200/60 dark:hover:bg-slate-800/60'
    }`;
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden animated-bg text-slate-800 dark:text-slate-200 select-none">
      {/* ─── 3D Sidebar ────────────────────────────────────────────────────────── */}
      <aside
        className={`${
          collapsed ? 'w-20' : 'w-64'
        } shrink-0 bg-white/95 dark:bg-[#0c121e]/95 backdrop-blur-xl border-r border-slate-200 dark:border-slate-800/80 flex flex-col z-30 transition-all duration-300 shadow-lg`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-200/80 dark:border-slate-800/80">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 p-0.5 shadow-md flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-extrabold text-base tracking-tight text-slate-900 dark:text-white flex items-center gap-1.5">
                  SecureLog <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">AI</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono tracking-wider">ENTERPRISE SOC</span>
              </div>
            )}
          </div>
          <button
            onClick={toggleSidebar}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Sections */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
          {/* Group 1: MAIN */}
          <div className="space-y-1">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                Command & Telemetry
              </div>
            )}
            <Link to="/dashboard" className={navItemClass('/dashboard')} title="Dashboard">
              <Activity className="w-4 h-4 shrink-0 mr-3" />
              {!collapsed && <span>Dashboard</span>}
            </Link>
            <Link to="/live-monitoring" className={navItemClass('/live-monitoring')} title="Live Monitoring">
              <Radio className="w-4 h-4 shrink-0 mr-3 text-emerald-500 animate-pulse" />
              {!collapsed && (
                <div className="flex items-center justify-between w-full">
                  <span>Live Stream</span>
                  <span className="text-[9px] font-mono font-bold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-500/30">
                    REALTIME
                  </span>
                </div>
              )}
            </Link>
            <Link to="/logs" className={navItemClass('/logs')} title="Events Explorer">
              <FileText className="w-4 h-4 shrink-0 mr-3" />
              {!collapsed && <span>Event Explorer</span>}
            </Link>
            <Link to="/alerts" className={navItemClass('/alerts')} title="Threat Alerts">
              <ShieldAlert className="w-4 h-4 shrink-0 mr-3 text-amber-500" />
              {!collapsed && (
                <div className="flex items-center justify-between w-full">
                  <span>Threat Alerts</span>
                  {unreadCount > 0 && (
                    <span className="text-[9px] font-bold bg-rose-500 text-white px-1.5 py-0.2 rounded-full">
                      {unreadCount}
                    </span>
                  )}
                </div>
              )}
            </Link>
            <Link to="/incidents" className={navItemClass('/incidents')} title="Incidents">
              <CheckCircle className="w-4 h-4 shrink-0 mr-3 text-indigo-500" />
              {!collapsed && <span>Incidents</span>}
            </Link>
            <Link to="/packet-analyzer" className={navItemClass('/packet-analyzer')} title="Packet Analyzer">
              <Wifi className="w-4 h-4 shrink-0 mr-3 text-cyan-500" />
              {!collapsed && <span>Packet Forensics</span>}
            </Link>
          </div>

          {/* Group 2: REPORTS */}
          <div className="space-y-1">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                Forensics & Reports
              </div>
            )}
            <button
              onClick={handleExportCSV}
              disabled={exportingCsv}
              className={`w-full ${navItemClass('/reports')} text-left`}
              title="Export Events CSV"
            >
              <Download className={`w-4 h-4 shrink-0 mr-3 text-blue-500 ${exportingCsv ? 'animate-bounce' : ''}`} />
              {!collapsed && <span>{exportingCsv ? 'Exporting...' : 'Export Events CSV'}</span>}
            </button>
          </div>

          {/* Group 3: SYSTEM */}
          <div className="space-y-1">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                Platform Admin
              </div>
            )}
            <Link to="/admin" className={navItemClass('/admin')} title="Administration">
              <Settings className="w-4 h-4 shrink-0 mr-3 text-slate-500" />
              {!collapsed && <span>Settings & Rules</span>}
            </Link>
          </div>
        </nav>

        {/* Sidebar Footer User Info */}
        <div className="p-3 border-t border-slate-200/80 dark:border-slate-800/80 bg-slate-50/50 dark:bg-[#0a0f1a]/60">
          <div className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between'}`}>
            <div className="flex items-center space-x-2.5 overflow-hidden">
              <div className="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-700/80 flex items-center justify-center text-slate-700 dark:text-slate-200 font-bold text-xs shrink-0 shadow-inner">
                <User className="w-4 h-4 text-blue-500" />
              </div>
              {!collapsed && (
                <div className="flex flex-col truncate">
                  <span className="text-xs font-semibold truncate text-slate-800 dark:text-slate-200">
                    {currentUser?.username || 'SecOps Admin'}
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {currentUser?.role || 'LEVEL 3 ANALYST'}
                  </span>
                </div>
              )}
            </div>
            {!collapsed && (
              <button
                onClick={handleLogout}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-500 hover:bg-rose-500/10 transition"
                title="Sign Out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* ─── Main Content Shell ─────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        {/* Global 3D Top Header */}
        <header className="h-16 bg-white/90 dark:bg-[#0b111e]/90 backdrop-blur-xl border-b border-slate-200/80 dark:border-slate-800/80 px-6 flex items-center justify-between z-20 shadow-sm transition-colors">
          {/* Breadcrumb & Context */}
          <div className="flex items-center space-x-3">
            <span className="text-[11px] font-mono uppercase tracking-wider text-blue-600 dark:text-blue-400 font-bold bg-blue-50 dark:bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
              {currentMeta.section}
            </span>
            <span className="text-slate-300 dark:text-slate-700">/</span>
            <div className="flex flex-col">
              <h1 className="text-sm font-bold tracking-tight text-slate-900 dark:text-white">
                {currentMeta.title}
              </h1>
              <span className="text-[10px] text-slate-400 hidden sm:inline-block">
                {currentMeta.desc}
              </span>
            </div>
          </div>

          {/* Center Search Bar with Ctrl+K */}
          <div className="hidden md:flex items-center w-72 lg:w-96">
            <div className="relative w-full">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search IPs, indicators, rule IDs..."
                className="w-full pl-9 pr-14 py-1.5 text-xs bg-slate-100 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 rounded-lg text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-blue-500 transition shadow-inner font-mono"
              />
              <div className="absolute right-2 top-2 flex items-center space-x-0.5 bg-slate-200/70 dark:bg-slate-800 px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-500 dark:text-slate-400">
                <span>Ctrl</span>
                <span>K</span>
              </div>
            </div>
          </div>

          {/* Right Action Cluster */}
          <div className="flex items-center space-x-3.5">
            {/* Live Status HUD Badge */}
            <div
              className={`flex items-center space-x-2 px-2.5 py-1 rounded-full text-xs font-mono font-medium border shadow-xs ${
                status === 'LIVE'
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                  : status === 'CONNECTING'
                  ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30'
                  : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
              }`}
            >
              <span className="relative flex h-2 w-2">
                {status === 'LIVE' && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                )}
                <span
                  className={`relative inline-flex rounded-full h-2 w-2 ${
                    status === 'LIVE'
                      ? 'bg-emerald-500'
                      : status === 'CONNECTING'
                      ? 'bg-amber-500'
                      : 'bg-rose-500'
                  }`}
                ></span>
              </span>
              <span className="text-[11px] font-bold tracking-wider">{status}</span>
            </div>

            {/* Notification Bell with Badge */}
            <div className="relative" ref={notifRef}>
              <button
                onClick={() => {
                  setShowNotifications(prev => !prev);
                  if (unreadCount > 0) setUnreadCount(0);
                }}
                className="p-2 rounded-xl text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/70 transition border border-transparent hover:border-slate-200 dark:hover:border-slate-700 relative"
                title="Notifications"
              >
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500 ring-2 ring-white dark:ring-slate-900 animate-pulse"></span>
                )}
              </button>

              {/* Notification Popover */}
              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-[#0f172a] rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl z-50 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
                  <div className="p-3 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-[#0a0f1a]">
                    <span className="text-xs font-bold text-slate-800 dark:text-white uppercase font-mono tracking-wide">
                      Live Telemetry Alerts
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {notifications.length} recent
                    </span>
                  </div>
                  <div className="max-h-72 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
                    {notifications.length === 0 ? (
                      <div className="p-6 text-center text-xs text-slate-400">
                        No recent threat notifications received.
                      </div>
                    ) : (
                      notifications.map(n => (
                        <div
                          key={n.id}
                          className="p-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer transition flex items-start space-x-2.5"
                          onClick={() => {
                            setShowNotifications(false);
                            navigate('/alerts');
                          }}
                        >
                          <AlertTriangle
                            className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${
                              n.severity === 'CRITICAL' ? 'text-rose-500' : 'text-amber-500'
                            }`}
                          />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate">
                              {n.title}
                            </p>
                            <p className="text-[10px] text-slate-400 font-mono mt-0.5">
                              {n.source_ip || 'Internal'} • {n.time}
                            </p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                  <div className="p-2 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-[#0a0f1a] text-center">
                    <button
                      onClick={() => {
                        setShowNotifications(false);
                        navigate('/alerts');
                      }}
                      className="text-[11px] text-blue-600 dark:text-blue-400 font-medium hover:underline"
                    >
                      View all threat alerts →
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Dark / Day Mode Toggle */}
            <button
              onClick={() => setIsDark(prev => !prev)}
              className="p-2 rounded-xl text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800/80 hover:bg-slate-200 dark:hover:bg-slate-700/80 border border-slate-200 dark:border-slate-700/60 transition shadow-xs"
              title={isDark ? 'Switch to Day Mode (Enterprise)' : 'Switch to Dark Mode (SOC)'}
            >
              {isDark ? (
                <Sun className="w-4 h-4 text-amber-400 transition-transform hover:rotate-45" />
              ) : (
                <Moon className="w-4 h-4 text-blue-600 transition-transform hover:-rotate-12" />
              )}
            </button>
          </div>
        </header>

        {/* Dynamic Page Outlet Container */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 relative">
          <Outlet />

          {/* 3D Elevated Alert Toast */}
          {toast && (
            <div
              onClick={() => navigate('/alerts')}
              className="fixed bottom-6 right-6 max-w-sm w-full bg-white dark:bg-[#0f172a] rounded-xl border border-rose-500/40 shadow-2xl p-4 z-50 cursor-pointer animate-in slide-in-from-bottom-5 duration-300 hover:scale-[1.02] transition-transform"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></div>
                  <span className="text-[11px] font-bold font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400">
                    {toast.severity || 'CRITICAL'} SECURITY THREAT
                  </span>
                </div>
                <button
                  onClick={e => {
                    e.stopPropagation();
                    setToast(null);
                  }}
                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-0.5"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              <h4 className="text-sm font-semibold text-slate-900 dark:text-white mt-1.5 truncate">
                {toast.title}
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2">
                {toast.description || `Source: ${toast.source_ip || 'N/A'}`}
              </p>
              <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                <span>IP: {toast.source_ip || 'N/A'}</span>
                <span className="text-blue-600 dark:text-blue-400 font-sans font-medium">Investigate →</span>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Layout;
