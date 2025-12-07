export const getDifficultyColor = (difficulty: string): string => {
  switch (difficulty.toLowerCase()) {
    case 'easy':
      return 'bg-green-100 text-green-800 border-green-300';
    case 'medium':
      return 'bg-yellow-100 text-yellow-800 border-yellow-300';
    case 'hard':
      return 'bg-orange-100 text-orange-800 border-orange-300';
    case 'insane':
      return 'bg-red-100 text-red-800 border-red-300';
    default:
      return 'bg-gray-100 text-gray-800 border-gray-300';
  }
};

export const getCategoryColor = (category: string): string => {
  const colors: Record<string, string> = {
    'Web Security': 'bg-blue-100 text-blue-800',
    'Windows': 'bg-cyan-100 text-cyan-800',
    'Linux': 'bg-purple-100 text-purple-800',
    'Forensics': 'bg-pink-100 text-pink-800',
    'Malware Analysis': 'bg-red-100 text-red-800',
    'Network Security': 'bg-indigo-100 text-indigo-800',
    'Cryptography': 'bg-violet-100 text-violet-800',
    'OSINT': 'bg-teal-100 text-teal-800',
    'Blue Team': 'bg-sky-100 text-sky-800',
    'Red Team': 'bg-rose-100 text-rose-800',
    'Purple Team': 'bg-fuchsia-100 text-fuchsia-800',
    'Cloud Security': 'bg-slate-100 text-slate-800',
    'Container Security': 'bg-emerald-100 text-emerald-800',
  };

  return colors[category] || 'bg-gray-100 text-gray-800';
};

export const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(date);
};

export const truncateText = (text: string, maxLength: number): string => {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
};
