import mongoose, { Schema, Document } from 'mongoose';

export interface IRoom extends Document {
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
  writeupSources: {
    url: string;
    platform: string;
    author?: string;
    scrapedAt: Date;
  }[];
  metadata: {
    estimatedTime?: string;
    points?: number;
    popularity?: number;
  };
  scrapedData: {
    summary?: string;
    keySteps?: string[];
    commonPitfalls?: string[];
  };
  lastUpdated: Date;
  createdAt: Date;
}

const RoomSchema: Schema = new Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  slug: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  difficulty: {
    type: String,
    enum: ['Easy', 'Medium', 'Hard', 'Insane', 'Unknown'],
    default: 'Unknown'
  },
  categories: [{
    type: String,
    index: true
  }],
  tags: [{
    type: String,
    index: true
  }],
  description: String,
  learningObjectives: [String],
  tools: [String],
  challenges: [String],
  techniques: [String],
  writeupSources: [{
    url: String,
    platform: String,
    author: String,
    scrapedAt: Date
  }],
  metadata: {
    estimatedTime: String,
    points: Number,
    popularity: Number
  },
  scrapedData: {
    summary: String,
    keySteps: [String],
    commonPitfalls: [String]
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Text search index
RoomSchema.index({
  name: 'text',
  title: 'text',
  description: 'text',
  tags: 'text'
});

export default mongoose.model<IRoom>('Room', RoomSchema);
