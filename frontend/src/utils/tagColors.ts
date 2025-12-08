// Tag Color System - Maps tags to color clusters for visual consistency

const RAW_COLOR_DATA_CSV = `endpoint_monitoring,Endpoint Monitoring,0,Monitoring,#B52626,1,Endpoint Monitoring
endpoint_security_monitoring,Endpoint Security Monitoring,0,Monitoring,#C22929,2,Endpoint Security Monitoring
integrity_monitoring,Integrity Monitoring,0,Monitoring,#CE2C2C,1,Integrity Monitoring
log_monitoring,Log Monitoring,0,Monitoring,#D43535,1,Log Monitoring
monitoring,Monitoring,0,Monitoring,#D74242,2,Monitoring
network_monitoring,Network Monitoring,0,Monitoring,#DA4E4E,1,Network Monitoring
network_security_monitoring,Network Security Monitoring,0,Monitoring,#DC5B5B,1,Network Security Monitoring
security_monitoring,Security Monitoring,0,Monitoring,#DF6868,3,Security Monitoring
system_monitoring,System Monitoring,0,Monitoring,#E27474,2,System Monitoring
cve,CVE,1,CVE,#AD4725,8,CVE|cve
ad_security,AD Security,2,security,#AD6925,1,AD Security
ai_security,AI Security,2,security,#AF6A25,3,AI Security
application_security,Application Security,2,security,#B26C26,3,Application Security
cloud_security,Cloud Security,2,security,#B66E27,2,Cloud Security
container_security,Container Security,2,security,#B97027,3,Container Security
cyber_security,Cyber Security,2,security,#BB7128,9,Cyber Security
database_security,Database Security,2,security,#CB7B2B,2,Database Security
defensive_security,Defensive Security,2,security,#CE7D2C,8,Defensive Security|defensive security
endpoint_security,Endpoint Security,2,security,#D3812F,9,Endpoint Security
linux_security,Linux Security,2,security,#D48536,2,Linux Security
offensive_security,Offensive Security,2,security,#D58738,9,Offensive Security
security_operations,Security Operations,2,security,#E0A76E,10,Security Operations
security_operations_center,Security Operations Center,2,security,#E1A970,2,Security Operations Center
windows_security,Windows Security,2,security,#E3B07C,5,Windows Security
docker,Docker,4,Docker Escape,#CCCC2B,18,Docker|docker
active_directory,Active Directory,5,Bypass,#88A924,28,Active Directory
ansible,Ansible,5,Bypass,#8AAC24,4,Ansible|ansible
apache,Apache,5,Bypass,#8AAC25,3,Apache
authentication,Authentication,5,Bypass,#8DB025,10,Authentication
automation,Automation,5,Bypass,#8EB126,9,Automation
burp_suite,Burp Suite,5,Bypass,#94B827,16,Burp Suite
ctf,CTF,5,Bypass,#9CC229,78,CTF|ctf
cryptography,Cryptography,5,Bypass,#9BC129,33,Cryptography|cryptography
devsecops,DevSecOps,5,Bypass,#A1C82A,11,DevSecOps
dfir,DFIR,5,Bypass,#A1C82A,23,DFIR
forensics,Forensics,20,Forensics,#CD2CCD,29,Forensics|forensics
git,Git,5,Bypass,#AAD32F,9,Git|git
incident_response,Incident Response,9,Detection,#30D359,69,Incident Response|incident response
linux,Linux,5,Bypass,#B1D640,150,Linux|linux
malware_analysis,Malware Analysis,11,Analysis,#35D4AC,36,Malware Analysis
metasploit,Metasploit,5,Bypass,#B3D845,24,Metasploit
network_security,Network Security,18,Network,#9754DB,16,Network Security
nmap,Nmap,5,Bypass,#B5D94B,56,Nmap|nmap
osint,OSINT,5,Bypass,#B7DA50,37,OSINT
owasp_top_10,OWASP Top 10,5,Bypass,#B8DA51,5,OWASP Top 10
penetration_testing,Penetration Testing,5,Bypass,#B9DB54,41,Penetration Testing
phishing,Phishing,5,Bypass,#B9DB55,11,Phishing|phishing
powershell,PowerShell,5,Bypass,#BADB57,9,PowerShell|Powershell
privilege_escalation,Privilege Escalation,5,Bypass,#BBDC58,214,Privilege Escalation|privilege escalation
python,Python,5,Bypass,#BCDC5B,35,Python|python
ransomware,Ransomware,5,Bypass,#BCDC5C,6,Ransomware
reverse_engineering,Reverse Engineering,5,Bypass,#BEDD60,42,Reverse Engineering
siem,SIEM,5,Bypass,#C1DF69,29,SIEM
splunk,Splunk,5,Bypass,#C2E06B,17,Splunk
sql_injection,SQL Injection,21,Injection,#DD60BE,42,SQL Injection|Sql Injection
ssh,SSH,5,Bypass,#C3E06C,40,SSH|ssh
web_exploitation,Web Exploitation,6,Exploitation,#ACE275,112,Web Exploitation|web exploitation
wireshark,Wireshark,5,Bypass,#CAE37D,21,Wireshark|wireshark
windows,Windows,20,Forensics,#DA51DA,79,Windows|windows`;

interface ColorData {
  hex: string;
  hsl: { h: number; s: number; l: number };
}

// Helper function to convert Hex to HSL
const hexToHsl = (hex: string): [number, number, number] => {
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
  r /= 255;
  g /= 255;
  b /= 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  let h = 0;
  let s = 0;
  const l = (max + min) / 2;

  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r:
        h = (g - b) / d + (g < b ? 6 : 0);
        break;
      case g:
        h = (b - r) / d + 2;
        break;
      case b:
        h = (r - g) / d + 4;
        break;
    }
    h /= 6;
  }
  return [Math.round(h * 360), Math.round(s * 100), Math.round(l * 100)];
};

// Parse CSV and build color map
const TAG_COLOR_MAP = new Map<string, ColorData>();

(() => {
  const lines = RAW_COLOR_DATA_CSV.trim().split('\n');
  lines.forEach(line => {
    const parts = line.split(',');
    if (parts.length >= 5) {
      const canonicalId = parts[0].trim().toLowerCase();
      const hexColor = parts[4].trim().toUpperCase();
      if (canonicalId && hexColor.startsWith('#')) {
        const [h, s, l] = hexToHsl(hexColor);
        TAG_COLOR_MAP.set(canonicalId, { hex: hexColor, hsl: { h, s, l } });
      }
    }
  });
})();

/**
 * Get color for a tag based on cluster mapping
 * @param tag - The tag name
 * @param type - The type of color to return (text, bg, border, bg-category)
 * @returns CSS color string
 */
export const getTagClusterColor = (tag: string, type: 'text' | 'bg' | 'border' | 'bg-category' = 'text'): string => {
  const normalizedTag = tag
    .toLowerCase()
    .trim()
    .replace(/[\s\W]+/g, '_')
    .replace(/^_|_$/g, '');

  let colorData = TAG_COLOR_MAP.get(normalizedTag);

  // Fuzzy match if exact match not found
  if (!colorData) {
    for (const [key, data] of TAG_COLOR_MAP.entries()) {
      if (key.includes(normalizedTag) || normalizedTag.includes(key)) {
        colorData = data;
        break;
      }
    }
  }

  if (colorData) {
    const { h } = colorData.hsl;
    switch (type) {
      case 'text':
        return `hsl(${h}, 80%, 85%)`;
      case 'bg':
        return `hsla(${h}, 50%, 12%, 0.7)`;
      case 'border':
        return `hsl(${h}, 85%, 60%)`;
      case 'bg-category':
        return `hsla(${h}, 60%, 15%, 0.8)`;
      default:
        return colorData.hex;
    }
  }

  // Toxic Green Fallback for unknown tags
  return type === 'bg' ? 'rgba(30, 41, 59, 0.7)' : type === 'border' ? '#39ff14' : '#f8fafc';
};

/**
 * Get difficulty color based on difficulty level
 * @param difficulty - Difficulty level (Easy, Medium, Hard, Insane)
 * @returns CSS color string
 */
export const getDifficultyColor = (difficulty: string): { bg: string; text: string; border: string } => {
  const difficultyMap: Record<string, { bg: string; text: string; border: string }> = {
    easy: { bg: 'hsla(142, 76%, 12%, 0.7)', text: 'hsl(142, 76%, 75%)', border: 'hsl(142, 76%, 50%)' },
    medium: { bg: 'hsla(45, 93%, 12%, 0.7)', text: 'hsl(45, 93%, 75%)', border: 'hsl(45, 93%, 50%)' },
    hard: { bg: 'hsla(24, 90%, 12%, 0.7)', text: 'hsl(24, 90%, 75%)', border: 'hsl(24, 90%, 50%)' },
    insane: { bg: 'hsla(0, 84%, 12%, 0.7)', text: 'hsl(0, 84%, 75%)', border: 'hsl(0, 84%, 50%)' },
  };

  return difficultyMap[difficulty.toLowerCase()] || { bg: 'rgba(30, 41, 59, 0.7)', text: '#f8fafc', border: '#39ff14' };
};
