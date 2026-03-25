import React, { useMemo, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import ThreatHunting from './pages/ThreatHunting';
import Innovations from './pages/Innovations';
import IncidentResponse from './pages/IncidentResponse';
import { useAppStore } from './store/useAppStore';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const navItems = [
  { path: '/' as const, label: 'Dashboard' },
  { path: '/threat-hunting' as const, label: 'Threat Hunting' },
  { path: '/innovations' as const, label: 'Innovations' },
  { path: '/incidents' as const, label: 'Incidents' },
];

export default function App() {
  const { darkMode, wsConnected } = useAppStore();
  const [authToken, setAuthToken] = useState<string>(() => localStorage.getItem('dashboard_access_token') || '');
  const [userRole, setUserRole] = useState<string>(() => localStorage.getItem('dashboard_user_role') || '');
  const [screen, setScreen] = useState<'landing' | 'login' | 'dashboard'>(authToken ? 'dashboard' : 'landing');
  const [loginForm, setLoginForm] = useState({ username: 'admin', password: 'admin123' });
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const isAuthed = useMemo(() => authToken.length > 0, [authToken]);

  const handleLogin = async () => {
    setIsLoggingIn(true);
    setLoginError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.access_token) {
        setLoginError(data?.error ? String(data.error) : `Login failed (${res.status})`);
        return;
      }
      const token = String(data.access_token);
      localStorage.setItem('dashboard_access_token', token);
      const role = String(data?.user?.role || '');
      if (role) {
        localStorage.setItem('dashboard_user_role', role);
        setUserRole(role);
      }
      setAuthToken(token);
      setScreen('dashboard');
    } catch {
      setLoginError('Login request failed. Please try again.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('dashboard_access_token');
    localStorage.removeItem('dashboard_user_role');
    setAuthToken('');
    setUserRole('');
    setScreen('landing');
  };

  if (screen === 'landing') {
    return (
      <div className="min-h-screen bg-[#F7FAFF] text-slate-900">
        <nav className="flex items-center justify-between px-6 py-4 border-b border-[#D8E3F7] bg-white">
          <div className="flex items-center gap-2">
            <span className="text-lg font-semibold text-slate-900">Parirakṣakaḥ</span>
          </div>
          <button
            onClick={() => setScreen('login')}
            className="px-4 py-2 rounded-lg bg-[#517EF9] text-white text-sm font-medium hover:bg-[#436FE8]"
          >
            Login
          </button>
        </nav>
        <main className="max-w-5xl mx-auto px-6 py-16">
          <div className="rounded-2xl border border-[#D8E3F7] bg-white p-10">
            <h1 className="text-4xl font-bold tracking-tight text-slate-900">Security Operations Platform</h1>
            <p className="mt-4 text-slate-600 max-w-2xl">
              Real-time detection, response, and cyber intelligence in one dashboard.
              Sign in to access live metrics, protected API integrations, and incident workflows.
            </p>
          </div>
        </main>
      </div>
    );
  }

  if (screen === 'login') {
    return (
      <div className="min-h-screen bg-[#F7FAFF] text-slate-900">
        <nav className="flex items-center justify-between px-6 py-4 border-b border-[#D8E3F7] bg-white">
          <span className="text-lg font-semibold text-slate-900">Parirakṣakaḥ</span>
          <button
            onClick={() => setScreen('landing')}
            className="px-3 py-1.5 rounded border border-[#D8E3F7] bg-white text-slate-600 text-sm"
          >
            Back
          </button>
        </nav>
        <main className="min-h-[80vh] grid place-items-center px-4">
          <div className="w-full max-w-xl rounded-2xl border border-[#D8E3F7] bg-white p-6">
            <h2 className="text-xl font-bold text-slate-900">Login</h2>
            <p className="mt-1 text-sm text-slate-500">Use your credentials to continue to dashboard.</p>
            <div className="mt-4 grid grid-cols-1 gap-3">
              <input
                value={loginForm.username}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, username: e.target.value }))}
                placeholder="Username"
                className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700 outline-none focus:border-[#517EF9]"
              />
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, password: e.target.value }))}
                placeholder="Password"
                className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700 outline-none focus:border-[#517EF9]"
              />
              <button
                onClick={handleLogin}
                disabled={isLoggingIn}
                className="rounded-lg bg-[#517EF9] text-white py-2 text-sm font-medium hover:bg-[#436FE8] disabled:opacity-70"
              >
                {isLoggingIn ? 'Signing in...' : 'Sign in'}
              </button>
              {loginError && <p className="text-xs text-red-600">{loginError}</p>}
              <p className="text-xs text-slate-500">Demo users: admin/admin123, analyst/analyst123, viewer/viewer123</p>
            </div>
          </div>
        </main>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <div className={`min-h-screen ${darkMode ? 'bg-[#F7FAFF] text-slate-900' : 'bg-[#F7FAFF] text-slate-900'}`}>
        {/* Top Nav */}
        <nav className="flex flex-wrap items-center justify-between gap-2 px-3 sm:px-6 py-3 border-b border-[#D8E3F7] bg-white/95 backdrop-blur">
          <div className="flex items-center gap-2 flex-shrink-0">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className="text-[#517EF9]">
              <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6l-9-4z" fill="currentColor" opacity="0.2" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
              <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span className="text-base sm:text-lg font-semibold tracking-tight text-slate-900">Parirakṣakaḥ</span>
          </div>
          <div className="flex gap-0.5 sm:gap-1 overflow-x-auto flex-shrink min-w-0">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg text-xs sm:text-sm font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-[#517EF9]/12 text-[#517EF9]'
                      : 'text-slate-500 hover:text-slate-800 hover:bg-[#EFF4FF]'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
          <div className="flex items-center gap-2 sm:gap-3 text-sm flex-shrink-0">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="text-slate-500 hidden sm:inline">{wsConnected ? 'Live' : 'Offline'}</span>
            {isAuthed && userRole && (
              <span className="px-2 py-0.5 rounded-full bg-[#EFF4FF] text-[#517EF9] border border-[#D8E3F7] text-xs uppercase">
                role: {userRole}
              </span>
            )}
            {isAuthed && (
              <button
                onClick={handleLogout}
                className="px-2.5 py-1 rounded border border-red-200 bg-red-50 text-red-700 text-xs"
              >
                Logout
              </button>
            )}
          </div>
        </nav>

        {/* Page Content */}
        <main className="p-3 sm:p-6">
          <Routes>
            <Route path="/" element={isAuthed ? <Dashboard /> : <Navigate to="/blocked" replace />} />
            <Route path="/threat-hunting" element={isAuthed ? <ThreatHunting /> : <Navigate to="/blocked" replace />} />
            <Route path="/innovations" element={isAuthed ? <Innovations /> : <Navigate to="/blocked" replace />} />
            <Route path="/incidents" element={isAuthed ? <IncidentResponse /> : <Navigate to="/blocked" replace />} />
            <Route path="/blocked" element={<div className="text-sm text-slate-600">Please login from the landing page.</div>} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
