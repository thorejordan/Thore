// Color mapping utility for tags and categories

const hexToHsl = (hex: string): { h: number; s: number; l: number } => {
  let r = 0, g = 0, b = 0;
  if (hex.length === 4) {
    r = parseInt(hex[1] + hex[1], 16);
    g = parseInt(hex[2] + hex[2], 16);
    b = parseInt(hex[3] + hex[3], 16);
  } else if (hex.length === 7) {
    r = parseInt(hex.substring(1, 3), 16);
    g = parseInt(hex.substring(3, 5), 16);
    b = parseInt(hex.substring(5, 7), 16);
  }
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  let h = 0, s = 0, l = (max + min) / 2;

  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = (g - b) / d + (g < b ? 6 : 0); break;
      case g: h = (b - r) / d + 2; break;
      case b: h = (r - g) / d + 4; break;
    }
    h /= 6;
  }
  return { h: Math.round(h * 360), s: Math.round(s * 100), l: Math.round(l * 100) };
};

// Comprehensive color mapping for security topics
const TOPIC_COLORS: Record<string, string> = {
  // Web Security (Blues)
  'web exploitation': '#3b82f6',
  'sql injection': '#2563eb',
  'xss': '#1d4ed8',
  'owasp': '#1e40af',
  'csrf': '#3b82f6',
  'xxe': '#60a5fa',
  'ssrf': '#93c5fd',

  // Network (Purples)
  'network': '#8b5cf6',
  'nmap': '#7c3aed',
  'enumeration': '#6d28d9',
  'reconnaissance': '#5b21b6',

  // Windows (Cyans)
  'windows': '#06b6d4',
  'active directory': '#0891b2',
  'powershell': '#0e7490',
  'bloodhound': '#155e75',

  // Linux (Greens)
  'linux': '#10b981',
  'privilege escalation': '#059669',
  'sudo': '#047857',
  'suid': '#065f46',

  // Forensics (Pinks)
  'forensics': '#ec4899',
  'memory': '#db2777',
  'wireshark': '#be185d',
  'autopsy': '#9f1239',

  // Malware (Reds)
  'malware analysis': '#ef4444',
  'reverse engineering': '#dc2626',
  'ghidra': '#b91c1c',
  'buffer overflow': '#991b1b',

  // Cryptography (Oranges)
  'cryptography': '#f59e0b',
  'hash cracking': '#d97706',
  'rsa': '#b45309',

  // Blue Team (Indigos)
  'blue team': '#6366f1',
  'siem': '#4f46e5',
  'splunk': '#4338ca',
  'incident response': '#3730a3',

  // OSINT (Ambers)
  'osint': '#f59e0b',
  'shodan': '#d97706',

  // Exploitation (Violets)
  'metasploit': '#8b5cf6',
  'meterpreter': '#7c3aed',

  // Cloud & Containers (Teals)
  'docker': '#14b8a6',
  'kubernetes': '#0d9488',
  'cloud': '#0f766e',

  // CTF (Lime)
  'ctf': '#84cc16',
  'steganography': '#65a30d',
};

const TAG_COLOR_MAP = new Map<string, { hex: string; hsl: { h: number; s: number; l: number } }>();

// Initialize color map
Object.entries(TOPIC_COLORS).forEach(([topic, hex]) => {
  const hsl = hexToHsl(hex);
  TAG_COLOR_MAP.set(topic.toLowerCase(), { hex, hsl });
});

export const getTagColor = (tag: string, type: 'text' | 'bg' | 'border' | 'bg-category' = 'text'): string => {
  const normalized = tag.toLowerCase().trim();

  // Try exact match first
  let colorData = TAG_COLOR_MAP.get(normalized);

  // Try partial match
  if (!colorData) {
    for (const [key, data] of TAG_COLOR_MAP.entries()) {
      if (normalized.includes(key) || key.includes(normalized)) {
        colorData = data;
        break;
      }
    }
  }

  if (colorData) {
    const { h, s, l } = colorData.hsl;
    switch (type) {
      case 'text': return `hsl(${h}, ${Math.min(s + 20, 100)}%, ${Math.min(l + 30, 85)}%)`;
      case 'bg': return `hsla(${h}, ${Math.max(s - 10, 40)}%, ${Math.max(l - 30, 8)}%, 0.6)`;
      case 'border': return `hsl(${h}, ${Math.min(s + 10, 100)}%, ${Math.min(l + 10, 60)}%)`;
      case 'bg-category': return `hsla(${h}, ${Math.max(s - 5, 50)}%, ${Math.max(l - 25, 12)}%, 0.8)`;
      default: return colorData.hex;
    }
  }

  // Fallback to difficulty-based or neutral colors
  return type === 'bg' ? 'rgba(30, 41, 59, 0.6)' :
         type === 'border' ? 'rgba(148, 163, 184, 0.3)' :
         '#cbd5e1';
};

export const getDifficultyColor = (difficulty: string): { text: string; bg: string; border: string } => {
  const diff = difficulty?.toLowerCase() || 'unknown';

  if (diff.includes('easy') || diff.includes('beginner')) {
    return {
      text: 'hsl(142, 70%, 75%)',
      bg: 'hsla(142, 60%, 12%, 0.7)',
      border: 'hsl(142, 70%, 50%)'
    };
  }
  if (diff.includes('medium') || diff.includes('intermediate')) {
    return {
      text: 'hsl(45, 90%, 75%)',
      bg: 'hsla(45, 70%, 12%, 0.7)',
      border: 'hsl(45, 90%, 55%)'
    };
  }
  if (diff.includes('hard') || diff.includes('advanced')) {
    return {
      text: 'hsl(0, 80%, 75%)',
      bg: 'hsla(0, 60%, 12%, 0.7)',
      border: 'hsl(0, 80%, 55%)'
    };
  }
  if (diff.includes('insane') || diff.includes('expert')) {
    return {
      text: 'hsl(280, 80%, 75%)',
      bg: 'hsla(280, 60%, 12%, 0.7)',
      border: 'hsl(280, 80%, 60%)'
    };
  }

  // Unknown
  return {
    text: '#94a3b8',
    bg: 'rgba(51, 65, 85, 0.6)',
    border: 'rgba(148, 163, 184, 0.3)'
  };
};
