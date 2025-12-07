import { Request, Response } from 'express';
import Room from '../models/Room';

export class RoomController {
  /**
   * Get all rooms with pagination and filtering
   */
  async getAllRooms(req: Request, res: Response): Promise<void> {
    try {
      const {
        page = 1,
        limit = 20,
        difficulty,
        search,
        tags,
        sortBy = 'name',
        sortOrder = 'asc'
      } = req.query;

      const query: any = {};

      // Filter by difficulty
      if (difficulty) {
        query.difficulty = difficulty;
      }

      // Filter by tags
      if (tags) {
        const tagArray = typeof tags === 'string' ? tags.split(',') : tags;
        query.tags = { $in: tagArray };
      }

      // Search across multiple fields
      if (search) {
        query.$text = { $search: search as string };
      }

      const sort: any = {};
      sort[sortBy as string] = sortOrder === 'desc' ? -1 : 1;

      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);
      const skip = (pageNum - 1) * limitNum;

      const [rooms, total] = await Promise.all([
        Room.find(query)
          .sort(sort)
          .skip(skip)
          .limit(limitNum)
          .lean(),
        Room.countDocuments(query)
      ]);

      res.json({
        success: true,
        data: rooms,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('Error fetching rooms:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching rooms',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Get a single room by slug
   */
  async getRoomBySlug(req: Request, res: Response): Promise<void> {
    try {
      const { slug } = req.params;
      const room = await Room.findOne({ slug }).lean();

      if (!room) {
        res.status(404).json({
          success: false,
          message: 'Room not found'
        });
        return;
      }

      res.json({
        success: true,
        data: room
      });
    } catch (error) {
      console.error('Error fetching room:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching room',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Get unique tags
   */
  async getTags(req: Request, res: Response): Promise<void> {
    try {
      const tags = await Room.distinct('tags');
      res.json({
        success: true,
        data: tags.sort()
      });
    } catch (error) {
      console.error('Error fetching tags:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching tags',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Get unique categories
   */
  async getCategories(req: Request, res: Response): Promise<void> {
    try {
      const categories = await Room.distinct('categories');
      res.json({
        success: true,
        data: categories.sort()
      });
    } catch (error) {
      console.error('Error fetching categories:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching categories',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Get statistics
   */
  async getStats(req: Request, res: Response): Promise<void> {
    try {
      const [
        total,
        byDifficulty,
        topTags,
        topTools
      ] = await Promise.all([
        Room.countDocuments(),
        Room.aggregate([
          { $group: { _id: '$difficulty', count: { $sum: 1 } } },
          { $sort: { _id: 1 } }
        ]),
        Room.aggregate([
          { $unwind: '$tags' },
          { $group: { _id: '$tags', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 20 }
        ]),
        Room.aggregate([
          { $unwind: '$tools' },
          { $group: { _id: '$tools', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 20 }
        ])
      ]);

      res.json({
        success: true,
        data: {
          total,
          byDifficulty,
          topTags,
          topTools
        }
      });
    } catch (error) {
      console.error('Error fetching stats:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching statistics',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
}

export default new RoomController();
