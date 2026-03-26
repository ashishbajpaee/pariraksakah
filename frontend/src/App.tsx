import React from 'react';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import ThreatHunting from './pages/ThreatHunting';
import Innovations from './pages/Innovations';
import IncidentResponse from './pages/IncidentResponse';
import NeuromorphicBrain from './pages/NeuromorphicBrain';
import { useAppStore } from './store/useAppStore';

const navItems = [
  { path: '/' as const, label: 'Dashboard' },
  { path: '/threat-hunting' as const, label: 'Threat Hunting' },
  { path: '/innovations' as const, label: 'Innovations' },
  { path: '/incidents' as const, label: 'Incidents' },
  { path: '/neuromorphic' as const, label: 'Neuromorphic Brain' },
];

export default function App() {
  const { darkMode, wsConnected } = useAppStore();

  return (
    <BrowserRouter>
      <div className={`min-h-screen ${darkMode ? 'bg-[#0F172A] text-gray-100' : 'bg-gray-50 text-gray-900'}`}>
        {/* Top Nav */}
        <nav className="flex flex-wrap items-center justify-between gap-2 px-3 sm:px-6 py-3 border-b border-gray-700/50 bg-[#0F172A]/90 backdrop-blur">
          <div className="flex items-center gap-2 flex-shrink-0">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className="text-[#6C63FF]">
              <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6l-9-4z" fill="currentColor" opacity="0.2" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
              <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span className="text-base sm:text-lg font-semibold tracking-tight">Parirakṣakaḥ</span>
          </div>
          <div className="flex gap-0.5 sm:gap-1 overflow-x-auto flex-shrink min-w-0">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg text-xs sm:text-sm font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-[#6C63FF]/20 text-[#6C63FF]'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700/50'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
          <div className="flex items-center gap-2 sm:gap-3 text-sm flex-shrink-0">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="text-gray-500 hidden sm:inline">{wsConnected ? 'Live' : 'Offline'}</span>
          </div>
        </nav>

        {/* Page Content */}
        <main className="p-3 sm:p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/threat-hunting" element={<ThreatHunting />} />
            <Route path="/innovations" element={<Innovations />} />
            <Route path="/incidents" element={<IncidentResponse />} />
            <Route path="/neuromorphic" element={<NeuromorphicBrain />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
