import { useState } from 'react';
import {
  Database,
  FileCode,
  Clock,
  BellRing,
  Shield,
  Save,
  CheckCircle2,
  Sliders,
} from 'lucide-react';

const Admin = () => {
  const [activeTab, setActiveTab] = useState('ingestion');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const tabs = [
    { id: 'ingestion', label: 'Data Ingestion', desc: 'Syslog ports & pipelines', icon: <Database className="w-4 h-4 mr-2" /> },
    { id: 'parsing', label: 'Log Parsing', desc: 'Custom regex & schemas', icon: <FileCode className="w-4 h-4 mr-2" /> },
    { id: 'retention', label: 'Data Lifecycle', desc: 'Storage tiers & retention', icon: <Clock className="w-4 h-4 mr-2" /> },
    { id: 'observability', label: 'Alerts & Integrations', desc: 'Webhooks & rate rules', icon: <BellRing className="w-4 h-4 mr-2" /> },
    { id: 'security', label: 'RBAC & Audit', desc: 'Roles, SSO & audit trails', icon: <Shield className="w-4 h-4 mr-2" /> },
  ];

  return (
    <div className="space-y-6">
      {/* ─── Page Top Bar ───────────────────────────────────────────────────────── */}
      <div className="card-3d p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
            <Sliders className="w-5 h-5 text-blue-500" />
            Infrastructure & Policy Administration
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Configure log collectors, parsing engines, ILM retention policies, and enterprise integrations.
          </p>
        </div>
        <button
          onClick={handleSave}
          className="btn-3d-primary px-5 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 shrink-0"
        >
          {saved ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <Save className="w-4 h-4" />}
          <span>{saved ? 'Configuration Saved!' : 'Save Changes'}</span>
        </button>
      </div>

      {/* ─── Tabs and Form Panels ───────────────────────────────────────────────── */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left Vertical Nav Rail */}
        <div className="w-full lg:w-72 shrink-0 space-y-2">
          {tabs.map(tab => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full text-left p-3.5 rounded-xl transition-all duration-150 flex items-start space-x-3 border ${
                  isActive
                    ? 'bg-white dark:bg-[#0f172a] text-blue-600 dark:text-blue-400 border-blue-500/30 shadow-md border-l-4 border-l-blue-600 dark:border-l-blue-500'
                    : 'bg-white/60 dark:bg-[#0c121e]/60 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border-slate-200 dark:border-slate-800 hover:bg-white dark:hover:bg-[#0f172a]'
                }`}
              >
                <div
                  className={`p-2 rounded-lg mt-0.5 ${
                    isActive
                      ? 'bg-blue-500/10 text-blue-600 dark:text-blue-400'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-400'
                  }`}
                >
                  {tab.icon}
                </div>
                <div>
                  <h4 className="text-xs font-bold leading-tight">{tab.label}</h4>
                  <p className="text-[10px] text-slate-400 font-mono mt-0.5">{tab.desc}</p>
                </div>
              </button>
            );
          })}
        </div>

        {/* Right Main Content Area */}
        <div className="flex-1 card-3d overflow-hidden">
          {/* Module 1: Data Ingestion */}
          {activeTab === 'ingestion' && (
            <div className="p-6 space-y-6 animate-in fade-in duration-200">
              <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Network Ingestion Stream Management
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Configure listeners for raw syslog telemetry, beats, and file tailing.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-900 dark:text-white">Syslog UDP/TCP Receiver</h4>
                      <p className="text-[10px] text-slate-400">Accept standard RFC 5424/3164 packet streams</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" defaultChecked className="sr-only peer" />
                      <div className="w-10 h-5 bg-slate-300 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                      Standard Port (UDP/TCP)
                    </label>
                    <input
                      type="number"
                      defaultValue={514}
                      className="input-3d w-full px-3 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                      TLS Mutual Auth Port (mTLS)
                    </label>
                    <input
                      type="number"
                      defaultValue={6514}
                      className="input-3d w-full px-3 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-900 dark:text-white">Local Host File Tailing</h4>
                      <p className="text-[10px] text-slate-400">Tail logs continuously from server filesystem</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" defaultChecked className="sr-only peer" />
                      <div className="w-10 h-5 bg-slate-300 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                      Watch Paths (comma separated)
                    </label>
                    <textarea
                      defaultValue="/var/log/syslog, /var/log/auth.log, /var/log/nginx/access.log"
                      rows={3}
                      className="input-3d w-full p-2 text-xs font-mono resize-none"
                    />
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
                <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider mb-3">
                  Database & Storage Connection Pool
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                      Primary Telemetry Store
                    </label>
                    <select className="input-3d w-full px-3 py-1.5 text-xs font-mono">
                      <option>PostgreSQL + AsyncPG (Active / Primary)</option>
                      <option>ClickHouse (High Throughput Columnar)</option>
                      <option>OpenSearch / Elasticsearch</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                      Encrypted Connection DSN
                    </label>
                    <input
                      type="password"
                      defaultValue="sqlite+aiosqlite:///./sql_app.db"
                      className="input-3d w-full px-3 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Module 2: Log Parsing */}
          {activeTab === 'parsing' && (
            <div className="p-6 space-y-6 animate-in fade-in duration-200">
              <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Format Profiles & Regex Pipeline
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Define normalization patterns and extract fields into structured JSON schema.
                </p>
              </div>

              <div className="space-y-3">
                <label className="block text-xs font-bold text-slate-800 dark:text-slate-200">
                  Active Dissection Profiles
                </label>
                <div className="flex flex-wrap gap-2">
                  <span className="px-3 py-1 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 text-xs font-mono font-semibold">
                    Linux Syslog (RFC 3164)
                  </span>
                  <span className="px-3 py-1 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 text-xs font-mono font-semibold">
                    Nginx Extended Access
                  </span>
                  <span className="px-3 py-1 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 text-xs font-mono font-semibold">
                    AWS CloudTrail
                  </span>
                  <span className="px-3 py-1 rounded-lg bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20 text-xs font-mono font-semibold">
                    Suricata IDS / EVE
                  </span>
                  <button className="px-3 py-1 rounded-lg border border-dashed border-slate-300 dark:border-slate-700 text-xs font-mono text-slate-500 hover:text-blue-500 hover:border-blue-500 transition">
                    + Add New Profile
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-bold text-slate-800 dark:text-slate-200">
                    Custom Regex Dissection Pattern
                  </label>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Syntax Validated ✓
                  </span>
                </div>
                <div className="relative">
                  <textarea
                    defaultValue="(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<service>\S+): (?P<message>.*)"
                    rows={4}
                    className="input-3d w-full p-3 font-mono text-xs text-blue-600 dark:text-blue-400 leading-relaxed resize-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-800 dark:text-slate-200 mb-1">
                  Timestamp Normalization Target
                </label>
                <select className="input-3d w-full sm:w-1/2 px-3 py-1.5 text-xs font-mono">
                  <option>UTC (Coordinated Universal Time)</option>
                  <option>Local Browser Time</option>
                  <option>America/New_York (EST/EDT)</option>
                  <option>Asia/Kolkata (IST)</option>
                </select>
              </div>
            </div>
          )}

          {/* Module 3: Data Lifecycle */}
          {activeTab === 'retention' && (
            <div className="p-6 space-y-6 animate-in fade-in duration-200">
              <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Index Lifecycle Management (ILM)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Automate hot, warm, cold storage tier transitions and retention limits.
                </p>
              </div>

              <div className="space-y-6">
                <div>
                  <div className="flex justify-between items-center mb-1.5">
                    <label className="text-xs font-bold text-slate-800 dark:text-slate-200">
                      Hot Tier (In-Memory / Fast NVMe)
                    </label>
                    <span className="text-xs font-mono font-bold text-blue-600 dark:text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                      7 Days
                    </span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="30"
                    defaultValue="7"
                    className="w-full h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-blue-600"
                  />
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1.5">
                    <label className="text-xs font-bold text-slate-800 dark:text-slate-200">
                      Warm Tier (Compressed Columnar Storage)
                    </label>
                    <span className="text-xs font-mono font-bold text-amber-600 dark:text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                      30 Days
                    </span>
                  </div>
                  <input
                    type="range"
                    min="7"
                    max="180"
                    defaultValue="30"
                    className="w-full h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-amber-500"
                  />
                </div>

                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div>
                    <h4 className="text-xs font-bold text-rose-600 dark:text-rose-400">
                      Hard Purge Safeguard (GDPR/Compliance)
                    </h4>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                      Permanently wipe raw event records exceeding maximum retention window.
                    </p>
                  </div>
                  <select className="input-3d px-3 py-1.5 text-xs font-mono font-bold text-rose-600 dark:text-rose-400">
                    <option>90 Days</option>
                    <option>180 Days</option>
                    <option>365 Days (1 Year)</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* Module 4: Observability Alerts */}
          {activeTab === 'observability' && (
            <div className="p-6 space-y-6 animate-in fade-in duration-200">
              <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Outbound Notification Integrations
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Route escalated threats to incident management systems and chat platforms.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                    Slack Incoming Webhook URL
                  </label>
                  <input
                    type="password"
                    defaultValue="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
                    className="input-3d w-full px-3 py-1.5 text-xs font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono font-medium text-slate-600 dark:text-slate-400 mb-1">
                    PagerDuty Integration Key
                  </label>
                  <input
                    type="password"
                    defaultValue="************************"
                    className="input-3d w-full px-3 py-1.5 text-xs font-mono"
                  />
                </div>
              </div>

              <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
                <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider mb-3">
                  Automated Correlation Rule Trigger
                </h4>
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-2 text-xs font-mono">
                  <span className="text-purple-600 dark:text-purple-400 font-bold">IF</span>
                  <select className="input-3d px-2 py-1 text-xs">
                    <option>[Severity == Critical]</option>
                  </select>
                  <span className="text-purple-600 dark:text-purple-400 font-bold">AND</span>
                  <select className="input-3d px-2 py-1 text-xs">
                    <option>[Velocity &gt; 100/min]</option>
                  </select>
                  <span className="text-purple-600 dark:text-purple-400 font-bold">THEN</span>
                  <select className="input-3d px-2 py-1 text-xs">
                    <option>Dispatch to PagerDuty</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* Module 5: RBAC & Security */}
          {activeTab === 'security' && (
            <div className="p-6 space-y-6 animate-in fade-in duration-200">
              <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Role-Based Access Control & Identity SSO
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Manage analyst privileges, enterprise SSO providers, and forensic audit logs.
                </p>
              </div>

              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="bg-slate-50 dark:bg-[#0c121e] text-slate-500 dark:text-slate-400 text-[10px] uppercase border-b border-slate-200 dark:border-slate-800">
                      <th className="px-4 py-3 font-semibold">Security Role</th>
                      <th className="px-4 py-3 font-semibold">Capabilities</th>
                      <th className="px-4 py-3 font-semibold">Scope</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    <tr>
                      <td className="px-4 py-3 font-bold text-slate-900 dark:text-white">SUPER_ADMIN</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 text-[10px] font-bold">
                          FULL READ/WRITE
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-500">Global Cluster</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-3 font-bold text-slate-900 dark:text-white">SECURITY_AUDITOR</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/30 text-[10px] font-bold">
                          READ + REPORT EXPORT
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-500">Global Telemetry</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-3 font-bold text-slate-900 dark:text-white">SOC_ANALYST_L1</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/30 text-[10px] font-bold">
                          READ ONLY
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-500">Live Feeds & Detections</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Audit Log Box */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#070b13] border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-blue-500" />
                    Internal Platform Audit Stream
                  </h4>
                  <span className="text-[10px] text-blue-600 dark:text-blue-400 font-mono">3 actions logged</span>
                </div>
                <div className="space-y-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                  <p>[10:45:12 UTC] admin_01 modified Regex Dissection profile 'Nginx Extended'</p>
                  <p>[09:12:05 UTC] system executed automated ILM rotation policy on cluster-01</p>
                  <p>[08:30:00 UTC] auditor_secops generated CSV bulk log export</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Admin;
