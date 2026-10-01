import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Layout from './components/Layout';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        {/* Protected Routes placeholder */}
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="logs" element={<div className="p-4">Logs (Phase 2)</div>} />
          <Route path="alerts" element={<div className="p-4">Alerts (Phase 2)</div>} />
          <Route path="incidents" element={<div className="p-4">Incidents (Phase 5)</div>} />
          <Route path="admin" element={<div className="p-4">Admin (Phase 4)</div>} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
