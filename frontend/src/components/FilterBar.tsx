import React, { useState, useEffect } from 'react';
import { Search, Filter, X } from 'lucide-react';
import type { FilterOptions } from '../types';
import { roomsApi } from '../services/api';

interface FilterBarProps {
  filters: FilterOptions;
  onFilterChange: (filters: Partial<FilterOptions>) => void;
}

const FilterBar: React.FC<FilterBarProps> = ({ filters, onFilterChange }) => {
  const [searchInput, setSearchInput] = useState(filters.search || '');
  const [availableTags, setAvailableTags] = useState<string[]>([]);
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    roomsApi.getTags().then((response) => {
      if (response.success) {
        setAvailableTags(response.data);
      }
    });
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onFilterChange({ search: searchInput });
  };

  const handleDifficultyChange = (difficulty: string) => {
    if (filters.difficulty === difficulty) {
      onFilterChange({ difficulty: undefined });
    } else {
      onFilterChange({ difficulty });
    }
  };

  const handleTagToggle = (tag: string) => {
    const currentTags = filters.tags || [];
    const newTags = currentTags.includes(tag)
      ? currentTags.filter((t) => t !== tag)
      : [...currentTags, tag];

    onFilterChange({ tags: newTags.length > 0 ? newTags : undefined });
  };

  const clearFilters = () => {
    setSearchInput('');
    onFilterChange({
      search: undefined,
      difficulty: undefined,
      tags: undefined,
    });
  };

  const hasActiveFilters = filters.search || filters.difficulty || (filters.tags && filters.tags.length > 0);

  return (
    <div className="bg-white rounded-lg shadow-md p-4 mb-6">
      {/* Search Bar */}
      <form onSubmit={handleSearchSubmit} className="flex gap-2 mb-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search rooms..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
        </div>
        <button
          type="submit"
          className="px-6 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium transition-colors"
        >
          Search
        </button>
        <button
          type="button"
          onClick={() => setShowFilters(!showFilters)}
          className={`px-4 py-2 border rounded-lg font-medium transition-colors flex items-center gap-2 ${
            showFilters
              ? 'bg-primary-50 border-primary-600 text-primary-700'
              : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
          }`}
        >
          <Filter className="w-5 h-5" />
          Filters
        </button>
        {hasActiveFilters && (
          <button
            type="button"
            onClick={clearFilters}
            className="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg font-medium transition-colors flex items-center gap-2"
          >
            <X className="w-5 h-5" />
            Clear
          </button>
        )}
      </form>

      {/* Filter Options */}
      {showFilters && (
        <div className="border-t border-gray-200 pt-4 space-y-4">
          {/* Difficulty Filter */}
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-2">Difficulty</h3>
            <div className="flex flex-wrap gap-2">
              {['Easy', 'Medium', 'Hard', 'Insane'].map((difficulty) => (
                <button
                  key={difficulty}
                  onClick={() => handleDifficultyChange(difficulty)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    filters.difficulty === difficulty
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  {difficulty}
                </button>
              ))}
            </div>
          </div>

          {/* Tags Filter */}
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-2">
              Popular Tags ({filters.tags?.length || 0} selected)
            </h3>
            <div className="flex flex-wrap gap-2 max-h-32 overflow-y-auto">
              {availableTags.slice(0, 30).map((tag) => (
                <button
                  key={tag}
                  onClick={() => handleTagToggle(tag)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                    filters.tags?.includes(tag)
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  #{tag}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Active Filters Summary */}
      {hasActiveFilters && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="flex flex-wrap gap-2 items-center">
            <span className="text-sm text-gray-600">Active filters:</span>
            {filters.search && (
              <span className="px-3 py-1 bg-primary-100 text-primary-800 rounded-full text-xs font-medium">
                Search: "{filters.search}"
              </span>
            )}
            {filters.difficulty && (
              <span className="px-3 py-1 bg-primary-100 text-primary-800 rounded-full text-xs font-medium">
                {filters.difficulty}
              </span>
            )}
            {filters.tags && filters.tags.length > 0 && (
              <span className="px-3 py-1 bg-primary-100 text-primary-800 rounded-full text-xs font-medium">
                {filters.tags.length} tag{filters.tags.length > 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default FilterBar;
