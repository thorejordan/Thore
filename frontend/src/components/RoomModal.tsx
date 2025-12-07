import React from 'react';
import { X, Shield, Tag, Wrench, Target, BookOpen, AlertTriangle, ExternalLink } from 'lucide-react';
import type { Room } from '../types';
import { getDifficultyColor, getCategoryColor, formatDate } from '../utils/helpers';

interface RoomModalProps {
  room: Room;
  onClose: () => void;
}

const RoomModal: React.FC<RoomModalProps> = ({ room, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-primary-600 to-primary-700 text-white p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex-1">
              <h2 className="text-3xl font-bold mb-2">{room.title}</h2>
              <p className="text-primary-100 font-mono text-sm">{room.slug}</p>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:bg-white hover:bg-opacity-20 rounded-full p-2 transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            <span
              className={`px-3 py-1 text-sm font-semibold rounded-full border bg-white ${getDifficultyColor(
                room.difficulty
              )}`}
            >
              {room.difficulty}
            </span>
            {room.categories.map((category) => (
              <span
                key={category}
                className={`px-3 py-1 text-sm font-medium rounded-full ${getCategoryColor(
                  category
                )}`}
              >
                {category}
              </span>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(90vh-200px)] p-6">
          {/* Description */}
          {room.description && (
            <section className="mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
              <p className="text-gray-700">{room.description}</p>
            </section>
          )}

          {/* Learning Objectives */}
          {room.learningObjectives.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Target className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Learning Objectives</h3>
              </div>
              <ul className="list-disc list-inside space-y-2 text-gray-700">
                {room.learningObjectives.map((objective, index) => (
                  <li key={index}>{objective}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Tools */}
          {room.tools.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Wrench className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Tools & Technologies</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {room.tools.map((tool, index) => (
                  <span
                    key={index}
                    className="px-3 py-1 bg-gray-100 text-gray-800 rounded-full text-sm font-medium"
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Techniques */}
          {room.techniques.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Techniques & Methods</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {room.techniques.map((technique, index) => (
                  <span
                    key={index}
                    className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-medium"
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Challenges */}
          {room.challenges.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Key Challenges</h3>
              </div>
              <ul className="list-disc list-inside space-y-2 text-gray-700">
                {room.challenges.map((challenge, index) => (
                  <li key={index}>{challenge}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Tags */}
          {room.tags.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Tag className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Tags</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {room.tags.map((tag, index) => (
                  <span
                    key={index}
                    className="px-2 py-1 bg-gray-200 text-gray-700 rounded text-xs font-medium"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Scraped Data */}
          {room.scrapedData?.summary && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <BookOpen className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Summary</h3>
              </div>
              <p className="text-gray-700 bg-gray-50 p-4 rounded-lg">{room.scrapedData.summary}</p>
            </section>
          )}

          {/* Writeup Sources */}
          {room.writeupSources.length > 0 && (
            <section className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <ExternalLink className="w-5 h-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900">Writeup Resources</h3>
              </div>
              <div className="space-y-2">
                {room.writeupSources.map((source, index) => (
                  <a
                    key={index}
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block p-3 bg-gray-50 hover:bg-gray-100 rounded-lg transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-sm font-medium text-primary-600">
                          {source.platform}
                        </span>
                        {source.author && (
                          <span className="text-sm text-gray-600"> by {source.author}</span>
                        )}
                      </div>
                      <ExternalLink className="w-4 h-4 text-gray-400" />
                    </div>
                  </a>
                ))}
              </div>
            </section>
          )}

          {/* Metadata */}
          <section className="pt-6 border-t border-gray-200">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500">Created:</span>
                <span className="ml-2 text-gray-900">{formatDate(room.createdAt)}</span>
              </div>
              <div>
                <span className="text-gray-500">Last Updated:</span>
                <span className="ml-2 text-gray-900">{formatDate(room.lastUpdated)}</span>
              </div>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="bg-gray-50 px-6 py-4 border-t border-gray-200">
          <div className="flex justify-between items-center">
            <a
              href={`https://tryhackme.com/room/${room.slug}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-600 hover:text-primary-700 font-medium text-sm flex items-center gap-2"
            >
              Visit on TryHackMe
              <ExternalLink className="w-4 h-4" />
            </a>
            <button
              onClick={onClose}
              className="px-6 py-2 bg-gray-200 hover:bg-gray-300 text-gray-800 rounded-lg font-medium transition-colors"
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
