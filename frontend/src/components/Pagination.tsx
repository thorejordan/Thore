import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { PaginationInfo } from '../types';

interface PaginationProps {
  pagination: PaginationInfo;
  onPageChange: (page: number) => void;
}

const Pagination: React.FC<PaginationProps> = ({ pagination, onPageChange }) => {
  const { page, pages, total, limit } = pagination;

  const getPageNumbers = () => {
    const delta = 2;
    const range: number[] = [];
    const rangeWithDots: (number | string)[] = [];

    for (let i = Math.max(2, page - delta); i <= Math.min(pages - 1, page + delta); i++) {
      range.push(i);
    }

    if (page - delta > 2) {
      rangeWithDots.push(1, '...');
    } else {
      rangeWithDots.push(1);
    }

    rangeWithDots.push(...range);

    if (page + delta < pages - 1) {
      rangeWithDots.push('...', pages);
    } else if (pages > 1) {
      rangeWithDots.push(pages);
    }

    return rangeWithDots;
  };

  const startItem = (page - 1) * limit + 1;
  const endItem = Math.min(page * limit, total);

  return (
    <div className="bg-white rounded-lg shadow-md p-4 mt-6">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Results Info */}
        <div className="text-sm text-gray-600">
          Showing <span className="font-medium">{startItem}</span> to{' '}
          <span className="font-medium">{endItem}</span> of{' '}
          <span className="font-medium">{total}</span> rooms
        </div>

        {/* Page Numbers */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page === 1}
            className="p-2 rounded-lg border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>

          {getPageNumbers().map((pageNum, index) => {
            if (pageNum === '...') {
              return (
                <span key={`dots-${index}`} className="px-2 text-gray-400">
                  ...
                </span>
              );
            }

            return (
              <button
                key={pageNum}
                onClick={() => onPageChange(pageNum as number)}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  pageNum === page
                    ? 'bg-primary-600 text-white'
                    : 'border border-gray-300 text-gray-700 hover:bg-gray-50'
                }`}
              >
                {pageNum}
              </button>
            );
          })}

          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page === pages}
            className="p-2 rounded-lg border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default Pagination;
