import React, { useState } from 'react';
import { Shield, Clock, ChevronDown, ChevronUp, Wrench, Target } from 'lucide-react';
import type { Room } from '../types';
import { getTagColor, getDifficultyColor } from '../utils/colorMapping';

interface RoomCardProps {
  room: Room;
  onClick: () => void;
}

const RoomCard: React.FC<RoomCardProps> = ({ room, onClick }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const primaryCategory = room.categories?.[0] || 'General';
  const diffColors = getDifficultyColor(room.difficulty);
  const categoryColors = {
    text: getTagColor(primaryCategory, 'text'),
    bg: getTagColor(primaryCategory, 'bg-category'),
    border: getTagColor(primaryCategory, 'border')
  };

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsExpanded(!isExpanded);
  };

  return (
    <div
      className="flex flex-col h-full bg-slate-900/40 backdrop-blur-md border rounded-xl hover:shadow-[0_0_20px_rgba(99,102,241,0.2)] transition-all duration-300 relative overflow-hidden group cursor-pointer"
      style={{ borderColor: 'rgba(255, 255, 255, 0.1)' }}
      onClick={onClick}
    >
      {/* Main Content */}
      <div className="p-5 flex flex-col h-full">
        {/* Header */}
        <div className="mb-3">
          <div className="flex items-start justify-between mb-2">
            <h3 className="text-base font-bold text-white leading-tight flex-1 group-hover:text-indigo-400 transition-colors">
              {room.title}
            </h3>
            <span
              className="ml-2 px-2.5 py-1 rounded-lg text-[10px] font-bold tracking-wider border shadow-sm whitespace-nowrap"
              style={{
                color: diffColors.text,
                backgroundColor: diffColors.bg,
                borderColor: diffColors.border
              }}
            >
              {room.difficulty}
            </span>
          </div>

          <div className="flex items-center gap-2 mb-2 flex-wrap">
            {room.categories?.slice(0, 2).map((cat, idx) => (
              <span
                key={`cat-${idx}`}
                className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider border shadow-sm"
                style={{
                  color: categoryColors.text,
                  borderColor: categoryColors.border,
                  backgroundColor: categoryColors.bg
                }}
              >
                {cat}
              </span>
            ))}
            {room.metadata?.estimatedTime && (
              <span className="text-[10px] text-slate-500 flex items-center ml-auto">
                <Clock className="w-3 h-3 mr-1 opacity-70" />
                {room.metadata.estimatedTime}
              </span>
            )}
          </div>
        </div>

        {/* Description */}
        <div className="flex-1 text-xs text-slate-400 leading-relaxed mb-3">
          <div className={`transition-all duration-300 ${isExpanded ? '' : 'line-clamp-3'}`}>
            {room.description || 'No description available.'}
          </div>
        </div>

        {/* Stats Row */}
        <div className="flex items-center gap-3 text-[10px] text-slate-500 mb-3 pb-3 border-b border-white/5">
          <div className="flex items-center gap-1">
            <Wrench className="w-3 h-3 opacity-70" />
            <span>{room.tools?.length || 0}</span>
          </div>
          <div className="flex items-center gap-1">
            <Target className="w-3 h-3 opacity-70" />
            <span>{room.learningObjectives?.length || 0}</span>
          </div>
          <div className="flex items-center gap-1">
            <Shield className="w-3 h-3 opacity-70" />
            <span>{room.techniques?.length || 0}</span>
          </div>
        </div>

        {/* Tags */}
        <div className="flex flex-wrap gap-1.5 mb-2">
          {room.tags?.slice(0, isExpanded ? 15 : 4).map((tag, idx) => {
            const tagColors = {
              text: getTagColor(tag, 'text'),
              bg: getTagColor(tag, 'bg'),
              border: getTagColor(tag, 'border')
            };
            return (
              <span
                key={`tag-${idx}`}
                className="text-[9px] px-2 py-0.5 rounded border backdrop-blur-sm font-medium"
                style={{
                  color: tagColors.text,
                  backgroundColor: tagColors.bg,
                  borderColor: tagColors.border
                }}
              >
                #{tag}
              </span>
            );
          })}
          {room.tags && room.tags.length > 4 && !isExpanded && (
            <span className="text-[9px] px-2 py-0.5 rounded bg-slate-800/50 text-slate-500 border border-slate-700">
              +{room.tags.length - 4}
            </span>
          )}
        </div>

        {/* Expand Toggle */}
        <button
          onClick={handleToggle}
          className="w-full mt-2 py-1.5 flex items-center justify-center text-[10px] text-slate-600 hover:text-indigo-400 transition-colors border-t border-white/5"
        >
          {isExpanded ? (
            <>
              <ChevronUp className="w-3 h-3 mr-1" />
              COLLAPSE
            </>
          ) : (
            <>
              <ChevronDown className="w-3 h-3 mr-1" />
              EXPAND
            </>
          )}
        </button>
      </div>

      {/* Hover Glow Effect */}
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/0 via-indigo-500/0 to-indigo-500/0 group-hover:from-indigo-500/5 group-hover:to-purple-500/5 transition-all duration-500 pointer-events-none rounded-xl" />
    </div>
  );
};

export default RoomCard;
