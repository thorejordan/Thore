import { useState, useEffect } from 'react';
import { roomsApi } from '../services/api';
import type { Room, FilterOptions, PaginationInfo } from '../types';

export const useRooms = (initialFilters?: FilterOptions) => {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [pagination, setPagination] = useState<PaginationInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterOptions>(initialFilters || { page: 1, limit: 20 });

  const fetchRooms = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await roomsApi.getAllRooms(filters);
      setRooms(response.data);
      setPagination(response.pagination);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch rooms');
      console.error('Error fetching rooms:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRooms();
  }, [filters]);

  const updateFilters = (newFilters: Partial<FilterOptions>) => {
    setFilters(prev => ({ ...prev, ...newFilters, page: 1 }));
  };

  const setPage = (page: number) => {
    setFilters(prev => ({ ...prev, page }));
  };

  const refetch = () => {
    fetchRooms();
  };

  return {
    rooms,
    pagination,
    loading,
    error,
    filters,
    updateFilters,
    setPage,
    refetch,
  };
};
