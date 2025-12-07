import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MOCK_ROOMS_DATA } from './data/mockRooms';

dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mock API routes
app.get('/api/rooms', (req: Request, res: Response) => {
  const { page = 1, limit = 20, difficulty, search } = req.query;

  let filteredRooms = [...MOCK_ROOMS_DATA];

  // Filter by difficulty
  if (difficulty) {
    filteredRooms = filteredRooms.filter(room => room.difficulty === difficulty);
  }

  // Filter by search
  if (search) {
    const searchLower = (search as string).toLowerCase();
    filteredRooms = filteredRooms.filter(room =>
      room.title.toLowerCase().includes(searchLower) ||
      room.description.toLowerCase().includes(searchLower)
    );
  }

  const pageNum = parseInt(page as string);
  const limitNum = parseInt(limit as string);
  const total = filteredRooms.length;
  const pages = Math.ceil(total / limitNum);

  res.json({
    success: true,
    data: filteredRooms,
    pagination: { page: pageNum, limit: limitNum, total, pages }
  });
});

app.get('/api/rooms/stats', (req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      total: MOCK_ROOMS_DATA.length,
      byDifficulty: [
        { _id: 'Easy', count: 2 },
        { _id: 'Medium', count: 1 }
      ],
      topTags: [
        { _id: 'windows', count: 1 },
        { _id: 'web', count: 1 }
      ],
      topTools: [
        { _id: 'metasploit', count: 2 },
        { _id: 'nmap', count: 1 }
      ]
    }
  });
});

app.get('/api/rooms/tags', (req: Request, res: Response) => {
  const allTags = MOCK_ROOMS_DATA.flatMap(room => room.tags);
  const uniqueTags = [...new Set(allTags)].sort();
  res.json({ success: true, data: uniqueTags });
});

app.get('/api/rooms/categories', (req: Request, res: Response) => {
  const allCategories = MOCK_ROOMS_DATA.flatMap(room => room.categories);
  const uniqueCategories = [...new Set(allCategories)].sort();
  res.json({ success: true, data: uniqueCategories });
});

app.get('/api/rooms/:slug', (req: Request, res: Response) => {
  const { slug } = req.params;
  const room = MOCK_ROOMS_DATA.find(r => r.slug === slug);

  if (!room) {
    res.status(404).json({ success: false, message: 'Room not found' });
    return;
  }

  res.json({ success: true, data: room });
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), mode: 'DEMO (Mock Data)' });
});

app.use((req: Request, res: Response) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Mode: DEMO with Mock Data (No MongoDB required)`);
  console.log(`🌐 API: http://localhost:${PORT}/api`);
  console.log(`💡 This is a demo version with 3 sample rooms`);
});
