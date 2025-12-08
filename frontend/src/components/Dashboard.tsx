import React, { useState, useMemo, useRef } from 'react';
import {
  Database,
  BarChart3,
  FileJson,
  Search,
  Upload,
  ChevronDown,
  ChevronUp,
  Table,
  Filter,
  Zap,
  Monitor,
  Server,
  Network,
  Terminal,
  CheckCircle2,
  AlertCircle,
  Loader2
} from 'lucide-react';
import { useRooms } from '../hooks/useRooms';
import RoomCard from './RoomCard';
import RoomModal from './RoomModal';
import type { Room } from '../types';

// --- CONSTANTS & CONFIG ---

export const ROLE_CONFIG = {
  windows_client_admin: { label: 'Client Admin', icon: Monitor, color: '#3b82f6' }, // Blue
  windows_server_admin: { label: 'Server Admin', icon: Server, color: '#8b5cf6' }, // Violet
  network_admin: { label: 'Network Admin', icon: Network, color: '#f59e0b' }, // Amber
  database_admin: { label: 'DB Admin', icon: Database, color: '#ec4899' }, // Pink
  linux_admin: { label: 'Linux Admin', icon: Terminal, color: '#10b981' }, // Emerald
};

export const THEME_ACCENT = '#39ff14'; // Toxic Green

const Dashboard: React.FC = () => {
  const { rooms, pagination, loading, error, filters, updateFilters, setPage } = useRooms({
    page: 1,
    limit: 50,
  });

  const [activeTab, setActiveTab] = useState('inventory');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRole, setSelectedRole] = useState<keyof typeof ROLE_CONFIG | null>(null);
  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null);
  const [notification, setNotification] = useState<{msg: string; type: 'success' | 'error'} | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Filter and Search Logic
  const filteredRooms = useMemo(() => {
    let data = [...rooms];

    // Search
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      data = data.filter(room => {
        const title = room.title?.toLowerCase() || '';
        const description = room.description?.toLowerCase() || '';
        const tags = room.tags?.map(t => t.toLowerCase()).join(' ') || '';
        return title.includes(term) || description.includes(term) || tags.includes(term);
      });
    }

    return data;
  }, [rooms, searchTerm]);

  const totalRooms = pagination?.total || 0;

  const showNotification = (msg: string, type: 'success' | 'error') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    showNotification(`Upload functionality coming soon!`, 'success');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  if (error) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4">
        <div className="bg-slate-900/90 border border-red-500 rounded-lg p-8 max-w-md w-full text-center">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Error Loading Rooms</h2>
          <p className="text-slate-400 mb-4">{error}</p>
          <p className="text-sm text-slate-500 font-mono">
            Backend server must be running on port 5000
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-slate-200 font-sans selection:bg-[#39ff14] selection:text-black relative">
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileUpload}
        accept=".json,.csv"
        className="hidden"
      />

      {/* Notification Toast */}
      {notification && (
        <div className={`fixed bottom-6 right-6 px-4 py-3 rounded-lg shadow-[0_0_20px_rgba(0,0,0,0.5)] border flex items-center z-50 animate-in fade-in slide-in-from-bottom-4 duration-300 ${
          notification.type === 'error'
            ? 'bg-red-950/90 border-red-500 text-red-200'
            : 'bg-slate-900/90 border-[#39ff14] text-[#39ff14]'
        }`}>
          {notification.type === 'error' ? <AlertCircle className="w-5 h-5 mr-2" /> : <CheckCircle2 className="w-5 h-5 mr-2" />}
          {notification.msg}
        </div>
      )}

      {/* Header */}
      <header className="bg-black/80 backdrop-blur-md border-b border-white/10 px-6 py-4 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg border border-[#39ff14]/30 shadow-[0_0_15px_rgba(57,255,20,0.2)] bg-[#39ff14]/10">
            <Zap className="w-6 h-6 text-[#39ff14]" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-wide uppercase font-mono">
              TryHackMe <span className="text-[#39ff14]">///</span> Console
            </h1>
            <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">
              Curriculum Intelligence v2.0
            </p>
          </div>
        </div>
        <div className="flex items-center bg-slate-900/50 p-1 rounded-lg border border-white/5">
          {[
            { id: 'dashboard', icon: BarChart3, label: 'Analytics' },
            { id: 'inventory', icon: Table, label: 'Inventory' },
            { id: 'schema', icon: FileJson, label: 'Schema' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 flex items-center space-x-2 ${
                activeTab === tab.id
                  ? 'bg-[#39ff14]/10 text-[#39ff14] border border-[#39ff14]/20 shadow-[0_0_10px_rgba(57,255,20,0.1)]'
                  : 'text-slate-500 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span className="hidden md:inline">{tab.label}</span>
            </button>
          ))}
        </div>
        <button
          onClick={() => fileInputRef.current?.click()}
          className="ml-4 px-4 py-2.5 rounded-lg text-sm font-bold bg-[#39ff14] hover:bg-[#32e012] text-black transition-all shadow-[0_0_20px_rgba(57,255,20,0.4)] flex items-center space-x-2"
        >
          <Upload className="w-4 h-4" />
          <span>UPLOAD_DATA</span>
        </button>
      </header>

      <main className="p-6 max-w-[1800px] mx-auto space-y-6">
        {/* DASHBOARD VIEW */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-900/40 border border-white/10 p-4 rounded-xl backdrop-blur-sm">
                <div className="flex justify-between">
                  <div>
                    <p className="text-slate-500 text-[10px] uppercase tracking-widest">Total Rooms</p>
                    <h3 className="text-3xl font-mono text-white mt-1">{totalRooms}</h3>
                  </div>
                  <Database className="text-slate-600" />
                </div>
              </div>
              <div className="bg-slate-900/40 border border-white/10 p-4 rounded-xl backdrop-blur-sm">
                <div className="flex justify-between">
                  <div>
                    <p className="text-slate-500 text-[10px] uppercase tracking-widest">Current Page</p>
                    <h3 className="text-3xl font-mono text-[#39ff14] mt-1 drop-shadow-[0_0_5px_rgba(57,255,20,0.5)]">
                      {pagination?.page || 1}
                    </h3>
                  </div>
                  <BarChart3 className="text-[#39ff14]" />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* INVENTORY VIEW */}
        {activeTab === 'inventory' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
              {/* Search */}
              <div className="relative flex-1 w-full md:w-auto md:max-w-md group">
                <Search className="absolute left-4 top-3.5 h-5 w-5 text-slate-500 group-focus-within:text-[#39ff14] transition-colors" />
                <input
                  type="text"
                  placeholder="Search query..."
                  className="w-full bg-slate-900/50 border border-white/10 text-slate-200 text-sm rounded-xl pl-12 pr-4 py-3 focus:ring-1 focus:ring-[#39ff14] focus:border-[#39ff14] focus:outline-none transition-all placeholder:text-slate-700 font-mono"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>

              {/* Role Filter Toolbar */}
              <div className="flex flex-wrap gap-2 items-center bg-slate-900/30 p-1.5 rounded-xl border border-white/5 w-full md:w-auto">
                <div className="flex items-center text-[10px] font-bold text-slate-500 uppercase tracking-widest px-3 mr-1">
                  <Filter className="w-3 h-3 mr-1.5" /> Target:
                </div>
                <button
                  onClick={() => setSelectedRole(null)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                    !selectedRole
                      ? 'bg-white/10 text-white shadow-sm'
                      : 'text-slate-500 hover:text-slate-200 hover:bg-white/5'
                  }`}
                >
                  ALL
                </button>
                {Object.keys(ROLE_CONFIG).map(role => (
                  <button
                    key={role}
                    onClick={() => setSelectedRole(role as keyof typeof ROLE_CONFIG)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase transition-all flex items-center ${
                      selectedRole === role
                        ? 'bg-[#39ff14]/20 text-[#39ff14] border border-[#39ff14]/30 shadow-[0_0_10px_rgba(57,255,20,0.2)]'
                        : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                    }`}
                  >
                    {ROLE_CONFIG[role as keyof typeof ROLE_CONFIG].label}
                  </button>
                ))}
              </div>
            </div>

            {/* Loading State */}
            {loading && (
              <div className="flex items-center justify-center py-20">
                <Loader2 className="w-12 h-12 text-[#39ff14] animate-spin" />
              </div>
            )}

            {/* GRID LAYOUT */}
            {!loading && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {filteredRooms.map((room, idx) => (
                  <RoomCard
                    key={`${room._id}-${idx}`}
                    room={room}
                    selectedRole={selectedRole}
                    onClick={() => setSelectedRoom(room)}
                  />
                ))}
                {filteredRooms.length === 0 && (
                  <div className="col-span-full py-20 text-center text-slate-600 font-mono">
                    NO_DATA_FOUND
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* SCHEMA VIEW */}
        {activeTab === 'schema' && (
          <div className="bg-slate-900/80 border border-white/10 rounded-xl p-6 font-mono text-xs text-slate-400">
            <h3 className="text-white font-bold mb-4 uppercase">Data Structure</h3>
            <pre className="text-[#39ff14] bg-black p-4 rounded border border-white/5 overflow-x-auto">
{`{
  "_id": "STRING",
  "name": "STRING",
  "title": "STRING",
  "slug": "STRING",
  "difficulty": "Easy | Medium | Hard | Insane",
  "categories": ["STRING"],
  "tags": ["STRING"],
  "description": "STRING",
  "learningObjectives": ["STRING"],
  "tools": ["STRING"],
  "challenges": ["STRING"],
  "techniques": ["STRING"]
}`}
            </pre>
          </div>
        )}
      </main>

      {/* Room Modal */}
      {selectedRoom && (
        <RoomModal room={selectedRoom} onClose={() => setSelectedRoom(null)} />
      )}
    </div>
  );
};

export default Dashboard;
