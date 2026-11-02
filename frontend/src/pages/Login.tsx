import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, Mail, AlertCircle, Sun, Moon, CheckCircle2 } from 'lucide-react';
import { authService } from '../services/api';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Dark/Day mode state in login
  const [isDark, setIsDark] = useState(() => {
    return localStorage.getItem('loganalyzer_theme') !== 'day';
  });

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('loganalyzer_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('loganalyzer_theme', 'day');
    }
  }, [isDark]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isRegister) {
        await authService.register({ username, password, email, role: 'ADMIN' });
        await authService.login({ username, password });
      } else {
        await authService.login({ username, password });
      }
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen animated-bg flex items-center justify-center p-4 sm:p-6 select-none relative overflow-hidden">
      {/* Background Decorative Lighting */}
      <div className="absolute top-1/4 -left-20 w-80 h-80 rounded-full bg-blue-500/10 blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-1/4 -right-20 w-80 h-80 rounded-full bg-indigo-500/10 blur-3xl pointer-events-none"></div>

      {/* Floating Theme Switcher at Top Right */}
      <div className="absolute top-6 right-6 z-20">
        <button
          onClick={() => setIsDark(prev => !prev)}
          className="p-2.5 rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 shadow-md text-slate-600 dark:text-slate-300 hover:scale-105 transition"
          title="Toggle Day/Dark mode"
        >
          {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-blue-600" />}
        </button>
      </div>

      {/* ─── 3D Authentication Card ─────────────────────────────────────────────── */}
      <div className="card-3d-elevated w-full max-w-md bg-white/95 dark:bg-[#0c121e]/95 backdrop-blur-xl p-8 shadow-2xl relative z-10 border border-slate-200 dark:border-slate-800">
        {/* Top Logo & Title */}
        <div className="flex flex-col items-center text-center">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-600 p-0.5 shadow-xl flex items-center justify-center mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>

          <h2 className="text-xl sm:text-2xl font-black tracking-tight text-slate-900 dark:text-white flex items-center gap-1.5">
            SecureLog <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-600 dark:text-blue-400 border border-blue-500/30">AI</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-1">
            {isRegister ? 'Register Security Operations Account' : 'Enterprise SOC Command Portal'}
          </p>
        </div>

        {/* Error Feedback */}
        {error && (
          <div className="mt-6 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 text-xs flex items-start space-x-2 animate-in fade-in duration-200 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
          {/* Username */}
          <div>
            <label className="block text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase mb-1">
              Analyst Username
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                required
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="e.g. secops_admin"
                className="input-3d w-full pl-9 pr-3 py-2 text-xs font-mono"
              />
            </div>
          </div>

          {/* Email (If register) */}
          {isRegister && (
            <div className="animate-in fade-in duration-150">
              <label className="block text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase mb-1">
                Corporate Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="analyst@enterprise.corp"
                  className="input-3d w-full pl-9 pr-3 py-2 text-xs font-mono"
                />
              </div>
            </div>
          )}

          {/* Password */}
          <div>
            <label className="block text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase mb-1">
              Security Token / Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="input-3d w-full pl-9 pr-3 py-2 text-xs font-mono"
              />
            </div>
          </div>

          {/* Submit Button */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="btn-3d-primary w-full py-2.5 rounded-lg text-xs font-bold tracking-wider uppercase flex items-center justify-center gap-2"
            >
              {loading && <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>}
              <span>{loading ? 'Authenticating...' : isRegister ? 'Create Credentials' : 'Authenticate Session'}</span>
            </button>
          </div>

          {/* Mode Switcher */}
          <div className="text-center pt-2">
            <button
              type="button"
              onClick={() => {
                setIsRegister(!isRegister);
                setError('');
              }}
              className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-mono transition"
            >
              {isRegister ? '← Back to Sign In' : 'New SOC analyst? Create account →'}
            </button>
          </div>
        </form>

        {/* Security Compliance Seal */}
        <div className="mt-8 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-center space-x-3 text-[10px] font-mono text-slate-400">
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-500" /> AES-256 GCM
          </span>
          <span>•</span>
          <span>Zero-Trust Protocol</span>
        </div>
      </div>
    </div>
  );
};

export default Login;
