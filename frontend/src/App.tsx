import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { useRequireAuth } from './hooks/useRequireAuth';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Entities from './pages/Entities';
import Pipeline from './pages/Pipeline';
import Incidents from './pages/Incidents';
import Chat from './pages/Chat';
import ConfigPage from './pages/Config';
import Help from './pages/Help';
import Methods from './pages/Methods';

function ProtectedLayout() {
  const { loading } = useRequireAuth();

  // Null while auth hydrates — no flash of the login redirect
  if (loading) return null;

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/entities" element={<Entities />} />
        <Route path="/pipeline" element={<Pipeline />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/chat" element={<Chat />} />
        <Route path="/environment" element={<Navigate to="/config" replace />} />
        <Route path="/config" element={<ConfigPage />} />
        <Route path="/help" element={<Help />} />
        <Route path="/methods" element={<Methods />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

export default function App() {
  const { isAuthenticated, loading } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={loading ? null : isAuthenticated ? <Navigate to="/" replace /> : <Login />}
      />
      <Route path="/*" element={<ProtectedLayout />} />
    </Routes>
  );
}
