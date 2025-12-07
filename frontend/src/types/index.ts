export interface Room {
  _id: string;
  name: string;
  slug: string;
  title: string;
  difficulty: 'Easy' | 'Medium' | 'Hard' | 'Insane' | 'Unknown';
  categories: string[];
  tags: string[];
  description?: string;
  learningObjectives: string[];
  tools: string[];
  challenges: string[];
  techniques: string[];
  writeupSources: WriteupSource[];
  metadata: {
    estimatedTime?: string;
    points?: number;
    popularity?: number;
  };
  scrapedData?: {
    summary?: string;
    keySteps?: string[];
    commonPitfalls?: string[];
  };
  lastUpdated: string;
  createdAt: string;
}

export interface WriteupSource {
  url: string;
  platform: string;
  author?: string;
  scrapedAt: string;
}

export interface PaginationInfo {
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface RoomsResponse {
  success: boolean;
  data: Room[];
  pagination: PaginationInfo;
}

export interface RoomResponse {
  success: boolean;
  data: Room;
}

export interface StatsResponse {
  success: boolean;
  data: {
    total: number;
    byDifficulty: { _id: string; count: number }[];
    topTags: { _id: string; count: number }[];
    topTools: { _id: string; count: number }[];
  };
}

export interface FilterOptions {
  search?: string;
  difficulty?: string;
  tags?: string[];
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}
