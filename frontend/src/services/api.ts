import axios from 'axios';
import type { RoomsResponse, RoomResponse, StatsResponse, FilterOptions } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const roomsApi = {
  getAllRooms: async (filters?: FilterOptions): Promise<RoomsResponse> => {
    const params = new URLSearchParams();

    if (filters?.search) params.append('search', filters.search);
    if (filters?.difficulty) params.append('difficulty', filters.difficulty);
    if (filters?.tags && filters.tags.length > 0) params.append('tags', filters.tags.join(','));
    if (filters?.page) params.append('page', filters.page.toString());
    if (filters?.limit) params.append('limit', filters.limit.toString());
    if (filters?.sortBy) params.append('sortBy', filters.sortBy);
    if (filters?.sortOrder) params.append('sortOrder', filters.sortOrder);

    const response = await api.get<RoomsResponse>(`/rooms?${params.toString()}`);
    return response.data;
  },

  getRoomBySlug: async (slug: string): Promise<RoomResponse> => {
    const response = await api.get<RoomResponse>(`/rooms/${slug}`);
    return response.data;
  },

  getTags: async (): Promise<{ success: boolean; data: string[] }> => {
    const response = await api.get('/rooms/tags');
    return response.data;
  },

  getCategories: async (): Promise<{ success: boolean; data: string[] }> => {
    const response = await api.get('/rooms/categories');
    return response.data;
  },

  getStats: async (): Promise<StatsResponse> => {
    const response = await api.get<StatsResponse>('/rooms/stats');
    return response.data;
  },
};

export default api;
