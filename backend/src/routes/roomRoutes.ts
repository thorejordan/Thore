import { Router } from 'express';
import roomController from '../controllers/roomController';

const router = Router();

// Get all rooms with filtering and pagination
router.get('/', roomController.getAllRooms.bind(roomController));

// Get statistics
router.get('/stats', roomController.getStats.bind(roomController));

// Get all tags
router.get('/tags', roomController.getTags.bind(roomController));

// Get all categories
router.get('/categories', roomController.getCategories.bind(roomController));

// Get single room by slug
router.get('/:slug', roomController.getRoomBySlug.bind(roomController));

export default router;
