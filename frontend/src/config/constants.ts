import { Monitor, Server, Network, Database, Terminal } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

// Theme Configuration
export const THEME_ACCENT = '#39ff14'; // Toxic Green

// Role Configuration
export interface RoleConfig {
  label: string;
  icon: LucideIcon;
  color: string;
}

export const ROLE_CONFIG: Record<string, RoleConfig> = {
  windows_client_admin: { label: 'Client Admin', icon: Monitor, color: '#3b82f6' }, // Blue
  windows_server_admin: { label: 'Server Admin', icon: Server, color: '#8b5cf6' }, // Violet
  network_admin: { label: 'Network Admin', icon: Network, color: '#f59e0b' }, // Amber
  database_admin: { label: 'DB Admin', icon: Database, color: '#ec4899' }, // Pink
  linux_admin: { label: 'Linux Admin', icon: Terminal, color: '#10b981' }, // Emerald
};

export type RoleKey = keyof typeof ROLE_CONFIG;
