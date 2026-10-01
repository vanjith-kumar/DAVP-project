const Dashboard = () => {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-semibold mb-4">Dashboard (Phase 1)</h2>
      <p className="text-gray-600">
        Welcome to SecureLog AI. This is the foundation phase. Advanced charts, live monitoring, and AI explanations will be added in subsequent phases.
      </p>
      
      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-blue-50 p-4 rounded border border-blue-100">
          <h3 className="font-semibold text-blue-800">Total Events</h3>
          <p className="text-2xl font-bold text-blue-900 mt-2">0</p>
        </div>
        <div className="bg-red-50 p-4 rounded border border-red-100">
          <h3 className="font-semibold text-red-800">Active Alerts</h3>
          <p className="text-2xl font-bold text-red-900 mt-2">0</p>
        </div>
        <div className="bg-green-50 p-4 rounded border border-green-100">
          <h3 className="font-semibold text-green-800">System Status</h3>
          <p className="text-2xl font-bold text-green-900 mt-2">Online</p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
