import React from 'react';
import { Shield, Tag, Wrench, Target } from 'lucide-react';
import type { Room } from '../types';
import { getDifficultyColor, getCategoryColor } from '../utils/helpers';

interface RoomCardProps {
  room: Room;
  onClick: () => void;
}

const RoomCard: React.FC<RoomCardProps> = ({ room, onClick }) => {
  return (
    <div
      onClick={onClick}
      className="bg-white rounded-lg shadow-md hover:shadow-xl transition-all duration-300 cursor-pointer overflow-hidden border border-gray-200 hover:border-primary-500 group"
    >
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <h3 className="text-xl font-bold text-gray-900 group-hover:text-primary-600 transition-colors mb-2">
              {room.title}
            </h3>
            <p className="text-sm text-gray-500 font-mono">{room.slug}</p>
          </div>
          <span
            className={`px-3 py-1 text-xs font-semibold rounded-full border ${getDifficultyColor(
              room.difficulty
            )}`}
          >
            {room.difficulty}
          </span>
        </div>

        {/* Description */}
        {room.description && (
          <p className="text-gray-600 text-sm mb-4 line-clamp-2">{room.description}</p>
        )}

        {/* Categories */}
        {room.categories.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {room.categories.slice(0, 3).map((category) => (
              <span
                key={category}
                className={`px-2 py-1 text-xs font-medium rounded ${getCategoryColor(category)}`}
              >
                {category}
              </span>
            ))}
            {room.categories.length > 3 && (
              <span className="px-2 py-1 text-xs font-medium rounded bg-gray-100 text-gray-600">
                +{room.categories.length - 3}
              </span>
            )}
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-4 pt-4 border-t border-gray-100">
          <div className="flex flex-col items-center">
            <Tag className="w-4 h-4 text-gray-400 mb-1" />
            <span className="text-xs text-gray-500">{room.tags.length} Tags</span>
          </div>
          <div className="flex flex-col items-center">
            <Wrench className="w-4 h-4 text-gray-400 mb-1" />
            <span className="text-xs text-gray-500">{room.tools.length} Tools</span>
          </div>
          <div className="flex flex-col items-center">
            <Target className="w-4 h-4 text-gray-400 mb-1" />
            <span className="text-xs text-gray-500">
              {room.learningObjectives.length} Goals
            </span>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="px-6 py-3 bg-gray-50 border-t border-gray-100">
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>Click for details</span>
          <Shield className="w-4 h-4 text-primary-500 opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
      </div>
    </div>
  );
};

export default RoomCard;
