import React, { useState } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';
import { useRooms } from '../hooks/useRooms';
import RoomCard from './RoomCard';
import RoomModal from './RoomModal';
import FilterBar from './FilterBar';
import Pagination from './Pagination';
import type { Room } from '../types';

const Dashboard: React.FC = () => {
  const { rooms, pagination, loading, error, filters, updateFilters, setPage } = useRooms({
    page: 1,
    limit: 20,
  });

  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null);

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-lg shadow-md p-8 max-w-md w-full text-center">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Error Loading Rooms</h2>
          <p className="text-gray-600 mb-4">{error}</p>
          <p className="text-sm text-gray-500">
            Make sure the backend server is running on port 5000
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">TryHackMe Dashboard</h1>
              <p className="text-gray-600 mt-1">
                Explore and learn from {pagination?.total || 0} TryHackMe rooms
              </p>
            </div>
            <div className="flex items-center gap-2">
              <a
                href="https://tryhackme.com"
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium transition-colors"
              >
                Visit TryHackMe
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Filter Bar */}
        <FilterBar filters={filters} onFilterChange={updateFilters} />

        {/* Loading State */}
        {loading && (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-12 h-12 text-primary-600 animate-spin" />
          </div>
        )}

        {/* Empty State */}
        {!loading && rooms.length === 0 && (
          <div className="bg-white rounded-lg shadow-md p-12 text-center">
            <AlertCircle className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-gray-900 mb-2">No Rooms Found</h2>
            <p className="text-gray-600">
              Try adjusting your filters or search query
            </p>
          </div>
        )}

        {/* Room Grid */}
        {!loading && rooms.length > 0 && (
          <>
            <div
              className="grid gap-6"
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
              <Pagination pagination={pagination} onPageChange={setPage} />
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
