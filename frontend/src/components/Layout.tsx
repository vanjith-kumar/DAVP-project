import { Outlet, Link, useNavigate } from 'react-router-dom';
import { Activity, ShieldAlert, FileText, Settings, Shield, LogOut } from 'lucide-react';
import { authService } from '../services/api';

const Layout = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    authService.logout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-gray-800">
          <Shield className="w-8 h-8 text-blue-500 mr-3" />
          <span className="text-xl font-bold">SecureLog AI</span>
        </div>
        <nav className="flex-1 overflow-y-auto py-4">
          <Link to="/dashboard" className="flex items-center px-6 py-3 hover:bg-gray-800 transition">
            <Activity className="w-5 h-5 mr-3" /> Dashboard
          </Link>
          <Link to="/logs" className="flex items-center px-6 py-3 hover:bg-gray-800 transition">
            <FileText className="w-5 h-5 mr-3" /> Live Logs
          </Link>
          <Link to="/alerts" className="flex items-center px-6 py-3 hover:bg-gray-800 transition">
            <ShieldAlert className="w-5 h-5 mr-3" /> Alerts
          </Link>
          <Link to="/admin" className="flex items-center px-6 py-3 hover:bg-gray-800 transition">
            <Settings className="w-5 h-5 mr-3" /> Admin
          </Link>
        </nav>
        <div className="p-4 border-t border-gray-800">
          <button 
            onClick={handleLogout}
            className="flex items-center w-full px-4 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded transition"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-16 bg-white shadow-sm flex items-center px-6">
          <h1 className="text-xl font-semibold text-gray-800">Phase 1 Foundation</h1>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;
