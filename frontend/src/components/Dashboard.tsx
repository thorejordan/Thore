import React, { useState } from 'react';
import { Loader2, AlertCircle, Zap, ExternalLink, Database } from 'lucide-react';
import { useRooms } from '../hooks/useRooms';
import RoomCard from './RoomCard';
import RoomModal from './RoomModal';
import FilterBar from './FilterBar';
import Pagination from './Pagination';
import type { Room } from '../types';

const Dashboard: React.FC = () => {
  const { rooms, pagination, loading, error, filters, updateFilters, setPage } = useRooms({
    page: 1,
    limit: 24,
  });

  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null);

  if (error) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4">
        <div className="bg-slate-900/80 backdrop-blur-md border border-red-500/30 rounded-xl p-8 max-w-md w-full text-center shadow-[0_0_30px_rgba(239,68,68,0.3)]">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Connection Failed</h2>
          <p className="text-slate-400 mb-4">{error}</p>
          <p className="text-sm text-slate-500 font-mono">
            Backend server required on port 5000
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-slate-200 font-sans selection:bg-indigo-500 selection:text-white">
      {/* Header */}
      <header className="bg-black/80 backdrop-blur-md border-b border-white/10 sticky top-0 z-40 shadow-lg">
        <div className="max-w-[1800px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg border border-indigo-500/30 shadow-[0_0_15px_rgba(99,102,241,0.3)] bg-indigo-500/10">
                <Zap className="w-6 h-6 text-indigo-400" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white tracking-wide uppercase font-mono">
                  TryHackMe <span className="text-indigo-400">///</span> Training Hub
                </h1>
                <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase flex items-center gap-2">
                  <Database className="w-3 h-3" />
                  {pagination?.total || 0} Modules Available
                </p>
              </div>
            </div>
            <a
              href="https://tryhackme.com"
              target="_blank"
              rel="noopener noreferrer"
              className="px-4 py-2.5 rounded-lg text-sm font-bold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-[0_0_20px_rgba(99,102,241,0.4)] flex items-center space-x-2 group"
            >
              <span>VISIT_THM</span>
              <ExternalLink className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </a>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1800px] mx-auto px-6 py-8">
        {/* Filter Bar */}
        <FilterBar filters={filters} onFilterChange={updateFilters} />

        {/* Loading State */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20">
            <Loader2 className="w-12 h-12 text-indigo-500 animate-spin mb-4" />
            <p className="text-slate-500 text-sm font-mono">LOADING_DATA...</p>
          </div>
        )}

        {/* Empty State */}
        {!loading && rooms.length === 0 && (
          <div className="bg-slate-900/40 backdrop-blur-md border border-white/10 rounded-xl p-12 text-center">
            <AlertCircle className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-white mb-2 font-mono">NO_DATA_FOUND</h2>
            <p className="text-slate-400">
              Try adjusting your filters or search query
            </p>
          </div>
        )}

        {/* Room Grid */}
        {!loading && rooms.length > 0 && (
          <>
            <div
              className="grid gap-5"
              style={{
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))'
              }}
            >
              {rooms.map((room) => (
                <RoomCard
                  key={room._id}
                  room={room}
                  onClick={() => setSelectedRoom(room)}
                />
              ))}
            </div>

            {/* Pagination */}
            {pagination && pagination.pages > 1 && (
              <div className="mt-8">
                <Pagination pagination={pagination} onPageChange={setPage} />
              </div>
            )}
          </>
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
