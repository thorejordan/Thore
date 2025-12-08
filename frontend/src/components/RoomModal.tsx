import React from 'react';
import { X, Shield, Tag, Wrench, Target, BookOpen, AlertTriangle, ExternalLink, Clock } from 'lucide-react';
import type { Room } from '../types';
import { getTagClusterColor, getDifficultyColor } from '../utils/tagColors';
import { formatDate } from '../utils/helpers';

interface RoomModalProps {
  room: Room;
  onClose: () => void;
}

const RoomModal: React.FC<RoomModalProps> = ({ room, onClose }) => {
  const difficultyColors = getDifficultyColor(room.difficulty);
  const primaryCategory = room.categories?.[0] || 'General';
  const categoryTextColor = getTagClusterColor(primaryCategory, 'text');
  const categoryBgColor = getTagClusterColor(primaryCategory, 'bg-category');
  const categoryBorderColor = getTagClusterColor(primaryCategory, 'border');

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-slate-900/95 backdrop-blur-md border border-white/10 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="bg-gradient-to-r from-slate-950 to-slate-900 border-b border-white/5 p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-2 font-mono uppercase tracking-wide">
                {room.title}
              </h2>
              <p className="text-slate-500 font-mono text-sm">{room.slug}</p>
            </div>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-[#39ff14] hover:bg-white/5 rounded-full p-2 transition-all"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            {/* Difficulty Badge */}
            <span
              className="px-3 py-1 text-xs font-bold tracking-wider rounded border"
              style={{
                color: difficultyColors.text,
                borderColor: difficultyColors.border,
                backgroundColor: difficultyColors.bg
              }}
            >
              {room.difficulty}
            </span>

            {/* Categories */}
            {room.categories.map((category) => {
              const catTextColor = getTagClusterColor(category, 'text');
              const catBgColor = getTagClusterColor(category, 'bg-category');
              const catBorderColor = getTagClusterColor(category, 'border');
              return (
                <span
                  key={category}
                  className="px-3 py-1 text-xs font-bold tracking-wider rounded border"
                  style={{
                    color: catTextColor,
                    borderColor: catBorderColor,
                    backgroundColor: catBgColor
                  }}
                >
                  {category}
                </span>
              );
            })}

            {/* Estimated Time */}
            {room.metadata?.estimatedTime && (
              <span className="px-3 py-1 text-xs font-mono text-slate-400 bg-slate-950/50 rounded border border-slate-800 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {room.metadata.estimatedTime}
              </span>
            )}
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(90vh-200px)] p-6 text-slate-200">
          {/* Description */}
          {room.description && (
            <section className="mb-6">
              <h3 className="text-sm font-bold text-[#39ff14] mb-3 uppercase tracking-widest font-mono">Description</h3>
              <p className="text-slate-300 text-sm leading-relaxed">{room.description}</p>
            </section>
          )}

          {/* Learning Objectives */}
          {room.learningObjectives.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Target className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Learning Objectives</h3>
              </div>
              <ul className="list-disc list-inside space-y-2 text-slate-300 text-sm">
                {room.learningObjectives.map((objective, index) => (
                  <li key={index} className="leading-relaxed">{objective}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Tools */}
          {room.tools.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Wrench className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Tools & Technologies</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {room.tools.map((tool, index) => {
                  const toolTextColor = getTagClusterColor(tool, 'text');
                  const toolBgColor = getTagClusterColor(tool, 'bg');
                  return (
                    <span
                      key={index}
                      className="px-2 py-1 rounded text-xs font-medium"
                      style={{
                        color: toolTextColor,
                        backgroundColor: toolBgColor
                      }}
                    >
                      {tool}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* Techniques */}
          {room.techniques.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Techniques & Methods</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {room.techniques.map((technique, index) => {
                  const techTextColor = getTagClusterColor(technique, 'text');
                  const techBgColor = getTagClusterColor(technique, 'bg');
                  return (
                    <span
                      key={index}
                      className="px-2 py-1 rounded text-xs font-medium"
                      style={{
                        color: techTextColor,
                        backgroundColor: techBgColor
                      }}
                    >
                      {technique}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* Challenges */}
          {room.challenges.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Key Challenges</h3>
              </div>
              <ul className="list-disc list-inside space-y-2 text-slate-300 text-sm">
                {room.challenges.map((challenge, index) => (
                  <li key={index} className="leading-relaxed">{challenge}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Tags */}
          {room.tags.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Tag className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Tags</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {room.tags.map((tag, index) => {
                  const tagTextColor = getTagClusterColor(tag, 'text');
                  const tagBgColor = getTagClusterColor(tag, 'bg');
                  return (
                    <span
                      key={index}
                      className="px-2 py-1 rounded text-xs font-medium"
                      style={{
                        color: tagTextColor,
                        backgroundColor: tagBgColor
                      }}
                    >
                      #{tag}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* Scraped Data */}
          {room.scrapedData?.summary && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <BookOpen className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Summary</h3>
              </div>
              <p className="text-slate-300 text-sm bg-slate-950/50 p-4 rounded-lg border border-white/5 leading-relaxed">
                {room.scrapedData.summary}
              </p>
            </section>
          )}

          {/* Writeup Sources */}
          {room.writeupSources.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <ExternalLink className="w-4 h-4 text-[#39ff14]" />
                <h3 className="text-sm font-bold text-[#39ff14] uppercase tracking-widest font-mono">Writeup Resources</h3>
              </div>
              <div className="space-y-2">
                {room.writeupSources.map((source, index) => (
                  <a
                    key={index}
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block p-3 bg-slate-950/50 hover:bg-slate-950/80 rounded-lg transition-all border border-white/5 hover:border-[#39ff14]/30"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-sm font-medium text-[#39ff14]">
                          {source.platform}
                        </span>
                        {source.author && (
                          <span className="text-sm text-slate-400"> by {source.author}</span>
                        )}
                      </div>
                      <ExternalLink className="w-4 h-4 text-slate-500" />
                    </div>
                  </a>
                ))}
              </div>
            </section>
          )}

          {/* Metadata */}
          <section className="pt-6 border-t border-white/5">
            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <span className="text-slate-500 uppercase tracking-widest">Created:</span>
                <span className="ml-2 text-slate-300">{formatDate(room.createdAt)}</span>
              </div>
              <div>
                <span className="text-slate-500 uppercase tracking-widest">Updated:</span>
                <span className="ml-2 text-slate-300">{formatDate(room.lastUpdated)}</span>
              </div>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="bg-slate-950/50 px-6 py-4 border-t border-white/5">
          <div className="flex justify-between items-center">
            <a
              href={`https://tryhackme.com/room/${room.slug}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#39ff14] hover:text-[#32e012] font-medium text-sm flex items-center gap-2 font-mono transition-colors"
            >
              Visit on TryHackMe
              <ExternalLink className="w-4 h-4" />
            </a>
            <button
              onClick={onClose}
              className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-medium transition-all text-sm border border-white/10"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RoomModal;
