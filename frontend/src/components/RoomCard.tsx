import React, { useState } from 'react';
import { Clock, ChevronDown, ChevronUp } from 'lucide-react';
import type { Room } from '../types';
import { ROLE_CONFIG, THEME_ACCENT } from './Dashboard';
import { getTagClusterColor, getDifficultyColor } from '../utils/tagColors';

interface RoomCardProps {
  room: Room;
  selectedRole: keyof typeof ROLE_CONFIG | null;
  onClick: () => void;
}

// Role Sidebar Component (Space Saving)
const RoleSidebar: React.FC<{ room: Room; selectedRole: keyof typeof ROLE_CONFIG | null }> = ({ room, selectedRole }) => {
  // Mock role data - in the real implementation, this would come from the room data
  // For now, we'll create a simple scoring system based on tags and categories
  const getRoleRelevance = (role: keyof typeof ROLE_CONFIG): number => {
    const tags = room.tags.map(t => t.toLowerCase());
    const categories = room.categories.map(c => c.toLowerCase());

    // Simple scoring logic based on keywords
    const scoreMap: Record<keyof typeof ROLE_CONFIG, string[]> = {
      windows_client_admin: ['windows', 'active directory', 'powershell', 'endpoint'],
      windows_server_admin: ['windows', 'server', 'active directory', 'iis'],
      network_admin: ['network', 'cisco', 'firewall', 'wireshark', 'packet'],
      database_admin: ['database', 'sql', 'mysql', 'postgresql', 'mongodb'],
      linux_admin: ['linux', 'bash', 'ssh', 'unix', 'shell'],
    };

    const keywords = scoreMap[role] || [];
    let score = 0;

    keywords.forEach(keyword => {
      if (tags.some(t => t.includes(keyword)) || categories.some(c => c.includes(keyword))) {
        score += 2;
      }
    });

    // Cap at 10
    return Math.min(score, 10);
  };

  return (
    <div className="absolute right-0 top-0 bottom-0 w-12 flex flex-col items-center justify-center gap-1.5 bg-slate-950/60 border-l border-white/5 backdrop-blur-sm z-10">
      {Object.entries(ROLE_CONFIG).map(([roleKey, config]) => {
        const score = getRoleRelevance(roleKey as keyof typeof ROLE_CONFIG);
        const isSelected = selectedRole === roleKey;
        const isRelevant = score >= 4;

        let opacity = 'opacity-20 grayscale';
        if (selectedRole) {
          opacity = isSelected
            ? 'opacity-100 grayscale-0 scale-110 drop-shadow-[0_0_8px_rgba(57,255,20,0.5)]'
            : 'opacity-10 grayscale';
        } else if (isRelevant) {
          opacity = 'opacity-80 hover:opacity-100 grayscale-0';
        }

        return (
          <div key={roleKey} className={`group relative transition-all duration-300 ${opacity}`}>
            <div
              className="peer p-1.5 rounded-md transition-colors"
              style={{ color: isSelected ? THEME_ACCENT : config.color }}
            >
              <config.icon className="w-4 h-4" />
            </div>

            {/* Minimal Score Indicator */}
            {score > 0 && (
              <span className={`absolute -top-1 -right-1 text-[8px] font-bold px-1 rounded-full bg-slate-900 text-white border border-slate-700 ${isSelected ? 'block' : 'hidden group-hover:block'}`}>
                {score}
              </span>
            )}

            {/* Hover Tooltip (Left side) */}
            {score > 0 && (
              <div className="absolute right-full mr-2 top-1/2 -translate-y-1/2 w-48 bg-slate-900 border border-slate-700 p-2 rounded shadow-xl opacity-0 peer-hover:opacity-100 pointer-events-none transition-opacity z-50">
                <div className="flex items-center gap-2 mb-1 border-b border-slate-800 pb-1">
                  <config.icon className="w-3 h-3" style={{ color: config.color }} />
                  <span className="text-[10px] font-bold text-slate-300 uppercase">{config.label}</span>
                  <span className="ml-auto text-xs font-mono text-white">{score}/10</span>
                </div>
                <p className="text-[10px] text-slate-400 leading-tight">
                  Relevance inferred based on tags and categories.
                </p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

const RoomCard: React.FC<RoomCardProps> = ({ room, selectedRole, onClick }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const primaryCategory = room.categories?.[0] || 'General';
  const mainAccentColor = getTagClusterColor(primaryCategory, 'border');
  const mainTextColor = getTagClusterColor(primaryCategory, 'text');
  const mainBgColor = getTagClusterColor(primaryCategory, 'bg-category');

  const difficultyColors = getDifficultyColor(room.difficulty);
  const estimatedTime = room.metadata?.estimatedTime || '1h';

  return (
    <div
      className="flex flex-col h-full bg-slate-900/30 backdrop-blur-md border rounded-xl hover:shadow-[0_0_15px_rgba(57,255,20,0.15)] transition-all duration-300 relative overflow-hidden group pr-12"
      style={{ borderColor: 'rgba(255, 255, 255, 0.1)' }}
    >
      {/* Role Sidebar Strip */}
      <RoleSidebar room={room} selectedRole={selectedRole} />

      {/* Main Content Area */}
      <div className="p-4 flex flex-col h-full z-0">
        {/* Header */}
        <div className="mb-2">
          <h3
            className="text-sm font-bold text-white leading-tight mb-2 line-clamp-2 group-hover:text-[color:var(--theme-accent)] transition-colors cursor-pointer"
            style={{ '--theme-accent': THEME_ACCENT } as React.CSSProperties}
            onClick={onClick}
          >
            {room.title}
          </h3>

          <div className="flex items-center gap-2 mb-2 flex-wrap">
            {/* Primary Category */}
            {room.categories?.slice(0, 1).map((cat, idx) => (
              <span
                key={`header-cat-${idx}`}
                className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider border shadow-sm"
                style={{ color: mainTextColor, borderColor: mainAccentColor, backgroundColor: mainBgColor }}
              >
                {cat}
              </span>
            ))}

            {/* Difficulty Badge */}
            <span
              className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider border shadow-sm"
              style={{
                color: difficultyColors.text,
                borderColor: difficultyColors.border,
                backgroundColor: difficultyColors.bg
              }}
            >
              {room.difficulty}
            </span>

            {/* Estimated Time */}
            {estimatedTime && (
              <span className="text-[10px] text-slate-500 flex items-center">
                <Clock className="w-3 h-3 mr-1 opacity-70" />
                {estimatedTime}
              </span>
            )}
          </div>
        </div>

        {/* Description */}
        <div className="flex-1 text-xs text-slate-400 leading-relaxed font-normal mb-3">
          <div className={`transition-all duration-500 ${isExpanded ? '' : 'line-clamp-3'}`}>
            {room.description || room.title}
          </div>
        </div>

        {/* Tags */}
        <div className="flex flex-wrap gap-1.5 mt-auto">
          {room.tags?.slice(0, isExpanded ? 20 : 3).map((tag, idx) => {
            const tagTextColor = getTagClusterColor(tag, 'text');
            const tagBgColor = getTagClusterColor(tag, 'bg');
            return (
              <span
                key={`tag-${idx}`}
                className="text-[10px] px-1.5 py-0.5 rounded border border-transparent backdrop-blur-sm"
                style={{ color: tagTextColor, backgroundColor: tagBgColor }}
              >
                #{tag}
              </span>
            );
          })}
        </div>

        {/* Toggle Button */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            setIsExpanded(!isExpanded);
          }}
          className="w-full mt-3 py-1 flex items-center justify-center text-[10px] text-slate-600 hover:text-[color:var(--theme-accent)] transition-colors"
          style={{ '--theme-accent': THEME_ACCENT } as React.CSSProperties}
        >
          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
      </div>
    </div>
  );
};

export default RoomCard;
