import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Room from '../models/Room';

dotenv.config();

interface EnrichmentData {
  learningObjectives: string[];
  tools: string[];
  challenges: string[];
  techniques: string[];
  description: string;
  technicalSummary: string;
}

// Generate comprehensive technical manual-style summary
function generateTechnicalSummary(slug: string, title: string, categories: string[], data: EnrichmentData): string {
  const parts: string[] = [];

  // Introduction - Technical Overview
  parts.push(`# ${title} - Technical Manual\n`);
  parts.push(`## 1. Introduction\n`);
  parts.push(`This room focuses on ${categories.join(', ') || 'cybersecurity fundamentals'} through practical, hands-on exploitation scenarios. `);
  parts.push(`Participants will develop proficiency in ${data.techniques.slice(0, 2).join(' and ')} while learning industry-standard methodologies and best practices.\n`);

  // Scope and Prerequisites
  parts.push(`\n### 1.1 Scope\n`);
  parts.push(`This training module covers:\n`);
  data.learningObjectives.slice(0, 3).forEach((obj, i) => {
    parts.push(`- ${obj}\n`);
  });

  parts.push(`\n### 1.2 Required Knowledge\n`);
  parts.push(`Before beginning this room, you should have:\n`);
  parts.push(`- Basic understanding of Linux/Windows command line operations\n`);
  parts.push(`- Familiarity with networking fundamentals (TCP/IP, ports, protocols)\n`);
  parts.push(`- Basic knowledge of web technologies (HTTP, HTML, JavaScript)\n`);
  parts.push(`- Experience with at least one programming/scripting language (Python, Bash, etc.)\n`);

  // Technical Environment
  parts.push(`\n## 2. Technical Environment & Setup\n`);
  parts.push(`\n### 2.1 Required Tools\n`);
  parts.push(`The following tools are essential for completing this room:\n\n`);
  data.tools.slice(0, 5).forEach(tool => {
    parts.push(`**${tool}**: `);
    // Tool-specific descriptions
    if (tool.toLowerCase().includes('nmap')) {
      parts.push(`Network discovery and security auditing tool. Essential for initial reconnaissance and service enumeration.\n`);
    } else if (tool.toLowerCase().includes('burp') || tool.toLowerCase().includes('burpsuite')) {
      parts.push(`Web application security testing suite. Critical for intercepting, analyzing, and modifying HTTP/S traffic.\n`);
    } else if (tool.toLowerCase().includes('metasploit')) {
      parts.push(`Penetration testing framework with extensive exploit database and post-exploitation capabilities.\n`);
    } else if (tool.toLowerCase().includes('sqlmap')) {
      parts.push(`Automated SQL injection and database takeover tool. Supports multiple database types and injection techniques.\n`);
    } else if (tool.toLowerCase().includes('john') || tool.toLowerCase().includes('hashcat')) {
      parts.push(`Advanced password recovery tool supporting numerous hash algorithms and attack modes.\n`);
    } else if (tool.toLowerCase().includes('ghidra') || tool.toLowerCase().includes('ida')) {
      parts.push(`Reverse engineering platform for analyzing compiled binaries and understanding program logic.\n`);
    } else if (tool.toLowerCase().includes('wireshark')) {
      parts.push(`Network protocol analyzer for packet capture and traffic analysis.\n`);
    } else {
      parts.push(`Key tool for this engagement. Ensure proper installation and configuration before proceeding.\n`);
    }
  });

  // Methodology
  parts.push(`\n## 3. Attack Methodology\n`);
  parts.push(`This section outlines the systematic approach to compromising the target environment.\n`);

  parts.push(`\n### 3.1 Reconnaissance Phase\n`);
  parts.push(`**Objective**: Gather comprehensive information about the target without triggering defensive mechanisms.\n\n`);
  parts.push(`**Procedure**:\n`);
  parts.push(`1. Perform passive reconnaissance using OSINT techniques\n`);
  parts.push(`2. Conduct active scanning to identify live hosts and open ports\n`);
  parts.push(`3. Enumerate services and determine version information\n`);
  parts.push(`4. Map the attack surface and identify potential entry points\n\n`);
  parts.push(`**Key Tools**: ${data.tools.slice(0, 3).join(', ')}\n`);
  parts.push(`**Expected Output**: Comprehensive list of accessible services, version numbers, and potential vulnerabilities\n`);

  parts.push(`\n### 3.2 Vulnerability Analysis\n`);
  parts.push(`**Objective**: Identify exploitable weaknesses in discovered services and applications.\n\n`);
  parts.push(`**Procedure**:\n`);
  parts.push(`1. Analyze service versions against known vulnerability databases (CVE, ExploitDB)\n`);
  parts.push(`2. Test for common misconfigurations and security weaknesses\n`);
  parts.push(`3. Identify custom applications and analyze for logic flaws\n`);
  parts.push(`4. Prioritize vulnerabilities based on exploitability and impact\n\n`);
  parts.push(`**Focus Areas**: ${data.techniques.slice(0, 3).join(', ')}\n`);

  parts.push(`\n### 3.3 Exploitation\n`);
  parts.push(`**Objective**: Gain unauthorized access to the target system.\n\n`);
  parts.push(`**Primary Attack Vector**: ${data.challenges[0] || 'Exploit identified vulnerabilities to achieve initial access'}\n\n`);
  parts.push(`**Procedure**:\n`);
  parts.push(`1. Develop or obtain appropriate exploit code\n`);
  parts.push(`2. Configure payload for reverse shell or command execution\n`);
  parts.push(`3. Execute exploit and verify successful compromise\n`);
  parts.push(`4. Establish persistent access channel\n\n`);
  parts.push(`**Critical Considerations**:\n`);
  parts.push(`- Ensure payload compatibility with target architecture\n`);
  parts.push(`- Configure listeners before executing reverse shell payloads\n`);
  parts.push(`- Document all actions for reporting purposes\n`);
  parts.push(`- Maintain operational security to avoid detection\n`);

  parts.push(`\n### 3.4 Post-Exploitation\n`);
  parts.push(`**Objective**: Escalate privileges and achieve complete system control.\n\n`);
  parts.push(`**Procedure**:\n`);
  parts.push(`1. Enumerate current user privileges and group memberships\n`);
  parts.push(`2. Identify privilege escalation vectors (SUID binaries, sudo misconfigurations, kernel exploits)\n`);
  parts.push(`3. Execute privilege escalation exploit to obtain root/SYSTEM access\n`);
  parts.push(`4. Extract sensitive data (credentials, flags, configuration files)\n`);
  parts.push(`5. Establish persistence mechanisms if required\n`);

  // Technical Details
  parts.push(`\n## 4. Technical Deep Dive\n`);

  if (data.techniques.length > 0) {
    parts.push(`\n### 4.1 Core Techniques\n`);
    data.techniques.slice(0, 3).forEach((technique, i) => {
      parts.push(`\n**${(i + 1)}.${(i + 1)} ${technique.toUpperCase()}**\n\n`);

      // Technique-specific details
      if (technique.toLowerCase().includes('sql')) {
        parts.push(`SQL injection exploits improper input validation in database queries. The attack manipulates SQL syntax to execute unauthorized commands.\n\n`);
        parts.push(`**Detection**: Test input fields with payloads like \`' OR '1'='1\`, \`1' UNION SELECT NULL--\`, and time-based payloads.\n\n`);
        parts.push(`**Exploitation Steps**:\n`);
        parts.push(`1. Identify injection point and confirm vulnerability\n`);
        parts.push(`2. Determine number of columns using ORDER BY or UNION SELECT\n`);
        parts.push(`3. Extract database schema information\n`);
        parts.push(`4. Dump sensitive tables (users, credentials, etc.)\n`);
        parts.push(`5. Attempt to escalate to command execution (xp_cmdshell, INTO OUTFILE)\n`);
      } else if (technique.toLowerCase().includes('xss')) {
        parts.push(`Cross-Site Scripting allows injection of malicious JavaScript into web pages viewed by other users.\n\n`);
        parts.push(`**Detection**: Test input fields with \`<script>alert(1)</script>\` and observe if script executes.\n\n`);
        parts.push(`**Exploitation Steps**:\n`);
        parts.push(`1. Identify reflection points in the application\n`);
        parts.push(`2. Test for filter bypass using encoding and obfuscation\n`);
        parts.push(`3. Craft payload to steal cookies or session tokens\n`);
        parts.push(`4. Set up listener to capture exfiltrated data\n`);
      } else if (technique.toLowerCase().includes('privilege') || technique.toLowerCase().includes('escalation')) {
        parts.push(`Privilege escalation exploits misconfigurations to elevate access from low-privileged to administrative accounts.\n\n`);
        parts.push(`**Common Vectors**:\n`);
        parts.push(`- SUID/SGID binaries with security flaws\n`);
        parts.push(`- Sudo misconfigurations allowing unauthorized command execution\n`);
        parts.push(`- Kernel exploits targeting unpatched vulnerabilities\n`);
        parts.push(`- Service exploits running with elevated privileges\n\n`);
        parts.push(`**Enumeration Commands**:\n`);
        parts.push(`- \`sudo -l\`: List sudo privileges\n`);
        parts.push(`- \`find / -perm -4000 2>/dev/null\`: Locate SUID binaries\n`);
        parts.push(`- \`uname -a\`: Check kernel version for known exploits\n`);
      } else {
        parts.push(`This technique represents a critical attack vector commonly exploited in real-world scenarios. Successful execution requires understanding both the theoretical foundation and practical implementation details.\n\n`);
        parts.push(`**Key Considerations**:\n`);
        parts.push(`- Thoroughly enumerate the target environment\n`);
        parts.push(`- Test in controlled environments before production exploitation\n`);
        parts.push(`- Document all findings for comprehensive reporting\n`);
      }
    });
  }

  // Challenges and Solutions
  parts.push(`\n## 5. Challenge Objectives\n`);
  if (data.challenges.length > 0) {
    data.challenges.forEach((challenge, i) => {
      parts.push(`\n### 5.${i + 1} ${challenge}\n`);
      parts.push(`This objective tests your ability to apply learned techniques in a practical scenario. `);
      parts.push(`Approach systematically: enumerate thoroughly, test methodically, and document findings. `);
      parts.push(`If stuck, revisit the reconnaissance phase and verify all services have been properly analyzed.\n`);
    });
  }

  // Best Practices
  parts.push(`\n## 6. Professional Best Practices\n`);
  parts.push(`\n### 6.1 Operational Security\n`);
  parts.push(`- Use VPN or proxy chains to anonymize traffic\n`);
  parts.push(`- Avoid triggering IDS/IPS through aggressive scanning\n`);
  parts.push(`- Clean up artifacts after testing (shells, uploaded files, logs)\n`);
  parts.push(`- Encrypt sensitive data during exfiltration\n\n`);

  parts.push(`### 6.2 Documentation\n`);
  parts.push(`Maintain detailed logs of:\n`);
  parts.push(`- All commands executed and their output\n`);
  parts.push(`- Vulnerabilities discovered with severity ratings\n`);
  parts.push(`- Exploitation attempts (both successful and failed)\n`);
  parts.push(`- Remediation recommendations for identified issues\n\n`);

  parts.push(`### 6.3 Legal and Ethical Considerations\n`);
  parts.push(`- Only test systems you have explicit authorization to assess\n`);
  parts.push(`- Respect scope limitations defined in engagement agreements\n`);
  parts.push(`- Report critical vulnerabilities to stakeholders immediately\n`);
  parts.push(`- Handle sensitive data responsibly and securely\n`);

  // Conclusion
  parts.push(`\n## 7. Conclusion\n`);
  parts.push(`This room provides hands-on experience with ${categories[0] || 'cybersecurity'} techniques used in professional penetration testing engagements. `);
  parts.push(`Successful completion demonstrates proficiency in reconnaissance, exploitation, and post-exploitation phases. `);
  parts.push(`Continue developing these skills through additional challenges and real-world practice in authorized environments.\n`);

  parts.push(`\n### Next Steps\n`);
  parts.push(`- Review similar rooms focusing on ${categories[0] || 'related topics'}\n`);
  parts.push(`- Practice skills in CTF competitions and bug bounty programs\n`);
  parts.push(`- Study CVE disclosures related to techniques learned\n`);
  parts.push(`- Pursue relevant certifications (OSCP, OSWE, CRTP, etc.)\n`);

  return parts.join('');
}

// Intelligent pattern-based enrichment with comprehensive descriptions
function enrichRoomData(slug: string, title: string, categories: string[]): EnrichmentData {
  const data: EnrichmentData = {
    learningObjectives: [],
    tools: [],
    challenges: [],
    techniques: [],
    description: '',
    technicalSummary: '',
  };

  const lowerSlug = slug.toLowerCase();

  // Web Security rooms
  if (lowerSlug.includes('sql') || lowerSlug.includes('sqli')) {
    data.description = 'Exploit SQL injection vulnerabilities to bypass authentication and extract database credentials.';
    data.learningObjectives.push('SQL injection fundamentals and advanced techniques', 'Database enumeration and exploitation', 'Bypassing WAF and input validation', 'Automated vs manual injection approaches');
    data.tools.push('sqlmap', 'burp suite', 'browser devtools', 'curl', 'python');
    data.challenges.push('Identify and exploit SQL injection vulnerabilities', 'Extract database credentials and sensitive information', 'Bypass authentication using SQL injection', 'Achieve remote code execution via SQL injection');
    data.techniques.push('union-based sql injection', 'error-based injection', 'blind sql injection', 'time-based sql injection', 'out-of-band sql injection');
  }

  if (lowerSlug.includes('xss') || lowerSlug.includes('cross-site')) {
    data.description = 'Master Cross-Site Scripting attacks to steal cookies and hijack user sessions.';
    data.learningObjectives.push('Understanding XSS attack vectors', 'Client-side security principles', 'Cookie theft and session hijacking', 'XSS filter bypass techniques');
    data.tools.push('burp suite', 'browser devtools', 'xss hunter', 'beef framework', 'zaproxy');
    data.challenges.push('Exploit reflected XSS vulnerabilities', 'Store malicious payloads for persistent XSS', 'Bypass XSS filters and sanitization', 'Steal session cookies using XSS');
    data.techniques.push('reflected xss', 'stored xss', 'dom-based xss', 'filter evasion', 'payload obfuscation');
  }

  if (lowerSlug.includes('owasp')) {
    data.description = 'Comprehensive training on OWASP Top 10 vulnerabilities including injection, authentication flaws, and misconfigurations.';
    data.learningObjectives.push('OWASP Top 10 vulnerability categories', 'Web application security fundamentals', 'Secure coding practices', 'Security testing methodologies');
    data.tools.push('burp suite', 'owasp zap', 'nikto', 'dirb', 'wfuzz', 'sqlmap');
    data.challenges.push('Identify and exploit injection flaws', 'Bypass broken authentication mechanisms', 'Exploit sensitive data exposure', 'Leverage security misconfigurations');
    data.techniques.push('injection attacks', 'broken authentication', 'sensitive data exposure', 'xxe', 'broken access control', 'security misconfiguration');
  }

  if (lowerSlug.includes('lfi') || lowerSlug.includes('rfi') || lowerSlug.includes('file-inclusion')) {
    data.description = 'Exploit file inclusion flaws to read sensitive files and achieve remote code execution through log poisoning.';
    data.learningObjectives.push('File inclusion vulnerability identification', 'Path traversal attack techniques', 'Log poisoning for RCE', 'PHP wrapper exploitation');
    data.tools.push('burp suite', 'curl', 'netcat', 'ffuf', 'wfuzz');
    data.challenges.push('Exploit LFI to read sensitive files', 'Achieve remote code execution via log poisoning', 'Use PHP wrappers for exploitation', 'Bypass LFI filters and restrictions');
    data.techniques.push('local file inclusion', 'remote file inclusion', 'path traversal', 'log poisoning', 'php wrapper exploitation', 'null byte injection');
  }

  if (lowerSlug.includes('ssrf')) {
    data.description = 'Abuse Server-Side Request Forgery to access internal resources and cloud metadata services.';
    data.learningObjectives.push('SSRF vulnerability identification', 'Internal network exploitation', 'Cloud metadata service abuse', 'SSRF defense bypass');
    data.tools.push('burp suite', 'curl', 'ngrok', 'collaborator');
    data.challenges.push('Exploit SSRF to access internal services', 'Retrieve cloud instance metadata', 'Port scanning via SSRF', 'Bypass SSRF protections');
    data.techniques.push('ssrf', 'internal port scanning', 'cloud metadata exploitation', 'filter bypass', 'dns rebinding');
  }

  if (lowerSlug.includes('csrf')) {
    data.description = 'Craft Cross-Site Request Forgery exploits to execute unauthorized actions on behalf of authenticated users.';
    data.learningObjectives.push('CSRF attack fundamentals', 'Token validation bypass', 'CSRF prevention mechanisms', 'Advanced CSRF exploitation');
    data.tools.push('burp suite', 'browser', 'csrf poc generator');
    data.challenges.push('Craft CSRF exploits for state-changing operations', 'Bypass CSRF token validation', 'Chain CSRF with other vulnerabilities');
    data.techniques.push('csrf', 'token bypass', 'referrer spoofing', 'same-site cookie bypass');
  }

  if (lowerSlug.includes('xxe')) {
    data.description = 'Exploit XML External Entity injection to disclose local files and perform SSRF attacks.';
    data.learningObjectives.push('XML parsing vulnerabilities', 'XXE exploitation techniques', 'Out-of-band XXE', 'Blind XXE detection');
    data.tools.push('burp suite', 'xxe injector', 'collaborator');
    data.challenges.push('Exploit XXE to read local files', 'Use XXE for SSRF attacks', 'Perform denial of service via XXE');
    data.techniques.push('xxe injection', 'out-of-band xxe', 'blind xxe', 'parameter entities', 'xxe to rce');
  }

  if (lowerSlug.includes('deserialization') || lowerSlug.includes('pickle')) {
    data.description = 'Craft malicious serialized objects to achieve remote code execution through insecure deserialization.';
    data.learningObjectives.push('Deserialization vulnerability concepts', 'Object injection attacks', 'Gadget chain construction', 'Language-specific deserialization');
    data.tools.push('ysoserial', 'burp suite', 'java decompiler', 'python pickle');
    data.challenges.push('Identify deserialization points', 'Craft malicious serialized objects', 'Achieve RCE via deserialization');
    data.techniques.push('insecure deserialization', 'object injection', 'gadget chains', 'java deserialization', 'python pickle exploitation');
  }

  // Network & Enumeration
  if (lowerSlug.includes('nmap') || lowerSlug.includes('scan')) {
    data.description = 'Master Nmap for port scanning, service detection, OS fingerprinting, and vulnerability enumeration.';
    data.learningObjectives.push('Network scanning methodologies', 'Service version detection', 'OS fingerprinting techniques', 'NSE script usage', 'Firewall evasion');
    data.tools.push('nmap', 'masscan', 'rustscan', 'unicornscan', 'zmap');
    data.challenges.push('Perform comprehensive port scans', 'Identify services and versions', 'Detect operating system', 'Use NSE scripts for vulnerability detection');
    data.techniques.push('syn scanning', 'tcp connect scanning', 'udp scanning', 'service enumeration', 'os detection', 'firewall evasion');
  }

  if (lowerSlug.includes('enum') || lowerSlug.includes('recon')) {
    data.description = 'Systematic enumeration and reconnaissance of networks, web applications, and system services.';
    data.learningObjectives.push('Systematic enumeration methodology', 'Service-specific enumeration', 'OSINT techniques', 'Automated reconnaissance');
    data.tools.push('nmap', 'gobuster', 'enum4linux', 'ldapsearch', 'smbclient', 'snmpwalk', 'dig', 'theHarvester');
    data.challenges.push('Enumerate all accessible services', 'Gather user and system information', 'Identify potential attack vectors');
    data.techniques.push('port scanning', 'service enumeration', 'smb enumeration', 'ldap enumeration', 'dns enumeration', 'web enumeration');
  }

  if (lowerSlug.includes('gobuster') || lowerSlug.includes('dirb') || lowerSlug.includes('directory')) {
    data.description = 'Discover hidden directories, files, and virtual hosts through web content fuzzing.';
    data.learningObjectives.push('Directory brute-forcing techniques', 'Custom wordlist creation', 'Recursive enumeration', 'Virtual host discovery');
    data.tools.push('gobuster', 'dirb', 'ffuf', 'wfuzz', 'dirbuster', 'feroxbuster');
    data.challenges.push('Discover hidden directories and files', 'Enumerate virtual hosts', 'Find backup files and sensitive data');
    data.techniques.push('directory brute-forcing', 'content discovery', 'fuzzing', 'wordlist optimization');
  }

  // Windows Exploitation
  if (categories.includes('Windows') || lowerSlug.includes('windows')) {
    data.description = 'Exploit Windows vulnerabilities and misconfigurations to escalate privileges and extract credentials.';
    data.learningObjectives.push('Windows architecture and security', 'Common Windows vulnerabilities', 'Privilege escalation techniques', 'Post-exploitation strategies');
    data.tools.push('nmap', 'metasploit', 'powershell', 'mimikatz', 'bloodhound', 'sharphound', 'winpeas', 'accesschk');
    data.challenges.push('Exploit Windows vulnerabilities', 'Escalate to SYSTEM privileges', 'Extract credentials from memory', 'Achieve persistence');
    data.techniques.push('windows exploitation', 'privilege escalation', 'credential dumping', 'lateral movement', 'persistence mechanisms');
  }

  if (lowerSlug.includes('active-directory') || lowerSlug.includes('ad-')) {
    data.description = 'Compromise Active Directory through Kerberos attacks, delegation abuse, and privilege escalation to Domain Admin.';
    data.learningObjectives.push('Active Directory fundamentals', 'AD enumeration techniques', 'Kerberos authentication attacks', 'Domain privilege escalation', 'AD persistence mechanisms');
    data.tools.push('bloodhound', 'sharphound', 'powerview', 'rubeus', 'mimikatz', 'impacket', 'crackmapexec', 'kerbrute', 'ldapdomaindump');
    data.challenges.push('Enumerate Active Directory environment', 'Perform Kerberoasting attack', 'Abuse delegation vulnerabilities', 'Achieve Domain Admin privileges', 'Implement persistence in AD');
    data.techniques.push('kerberoasting', 'asreproasting', 'pass-the-hash', 'pass-the-ticket', 'golden ticket', 'silver ticket', 'dcsync', 'zerologon', 'printnightmare');
  }

  if (lowerSlug.includes('powershell')) {
    data.description = 'Leverage PowerShell for offensive operations, AMSI bypass, and post-exploitation.';
    data.learningObjectives.push('PowerShell scripting for pentesting', 'PowerShell obfuscation techniques', 'AMSI and logging bypass', 'PowerShell exploitation frameworks');
    data.tools.push('powershell', 'powerview', 'powerup', 'empire', 'powersploit', 'nishang', 'invoke-obfuscation');
    data.challenges.push('Use PowerShell for system enumeration', 'Bypass AMSI and script block logging', 'Exploit using PowerShell frameworks');
    data.techniques.push('powershell scripting', 'amsi bypass', 'obfuscation', 'fileless malware', 'powershell exploitation');
  }

  if (lowerSlug.includes('bloodhound')) {
    data.description = 'Visualize Active Directory attack paths using BloodHound to identify privilege escalation routes.';
    data.learningObjectives.push('BloodHound data collection', 'Graph database querying', 'Attack path identification', 'Custom Cypher queries');
    data.tools.push('bloodhound', 'sharphound', 'azurehound', 'neo4j');
    data.challenges.push('Collect and analyze AD data', 'Identify paths to Domain Admin', 'Find exploitable ACL misconfigurations');
    data.techniques.push('graph theory', 'acl exploitation', 'delegation abuse', 'group policy abuse');
  }

  if (lowerSlug.includes('eternal') || lowerSlug.includes('blue')) {
    data.description = 'Exploit EternalBlue (MS17-010) SMB vulnerability for remote code execution.';
    data.learningObjectives.push('SMB protocol vulnerabilities', 'EternalBlue exploitation', 'Metasploit framework usage', 'DoublePulsar backdoor');
    data.tools.push('nmap', 'metasploit', 'smbclient', 'auxiliary modules');
    data.challenges.push('Identify vulnerable SMB services', 'Exploit MS17-010', 'Gain remote code execution', 'Post-exploitation activities');
    data.techniques.push('smb exploitation', 'eternalblue', 'buffer overflow', 'remote code execution');
  }

  // Linux Exploitation
  if (categories.includes('Linux') || lowerSlug.includes('linux')) {
    data.description = 'Exploit Linux misconfigurations and vulnerabilities to escalate from user to root privileges.';
    data.learningObjectives.push('Linux security architecture', 'File system permissions', 'Privilege escalation methodologies', 'Linux post-exploitation');
    data.tools.push('linpeas', 'linenum', 'linuxprivchecker', 'pspy', 'gtfobins', 'unix-privesc-check');
    data.challenges.push('Enumerate Linux system', 'Identify privilege escalation vectors', 'Escalate to root privileges', 'Maintain persistent access');
    data.techniques.push('suid exploitation', 'sudo abuse', 'kernel exploits', 'cron jobs', 'nfs misconfiguration', 'docker escape');
  }

  if (lowerSlug.includes('privesc') || lowerSlug.includes('privilege')) {
    data.description = 'Escalate privileges from standard user to administrator/root through systematic exploitation.';
    data.learningObjectives.push('Privilege escalation methodology', 'System enumeration techniques', 'Common privilege escalation vectors', 'Automated vs manual enumeration');
    data.tools.push('linpeas', 'winpeas', 'pspy', 'gtfobins', 'lolbas', 'sudo -l', 'accesschk');
    data.challenges.push('Perform thorough system enumeration', 'Identify privilege escalation paths', 'Escalate to root/administrator', 'Document exploitation process');
    data.techniques.push('privilege escalation', 'suid/sgid exploitation', 'sudo abuse', 'kernel exploits', 'scheduled tasks', 'service exploits', 'registry exploitation');
  }

  if (lowerSlug.includes('sudo')) {
    data.description = 'Abuse sudo misconfigurations and leverage GTFOBins for privilege escalation to root.';
    data.learningObjectives.push('Sudo security model', 'GTFOBins usage', 'Sudo token manipulation', 'Sudo policy analysis');
    data.tools.push('gtfobins', 'sudo', 'sudoedit');
    data.challenges.push('Identify sudo misconfigurations', 'Escalate privileges via sudo', 'Bypass sudo restrictions');
    data.techniques.push('sudo abuse', 'gtfobins', 'sudo token reuse', 'sudo policy bypass');
  }

  if (lowerSlug.includes('suid') || lowerSlug.includes('sgid')) {
    data.description = 'Identify and exploit SUID/SGID binaries to gain root-level access.';
    data.learningObjectives.push('SUID/SGID concepts', 'Binary exploitation basics', 'GTFOBins for SUID abuse', 'Custom SUID exploitation');
    data.tools.push('find', 'gtfobins', 'strings', 'ltrace', 'strace');
    data.challenges.push('Find SUID binaries', 'Exploit misconfigured SUID binaries', 'Achieve root access');
    data.techniques.push('suid exploitation', 'sgid abuse', 'binary analysis', 'path hijacking');
  }

  if (lowerSlug.includes('kernel')) {
    data.description = 'Exploit kernel vulnerabilities including Dirty COW for local privilege escalation.';
    data.learningObjectives.push('Kernel architecture basics', 'Kernel vulnerability identification', 'Kernel exploit compilation', 'Exploit stability considerations');
    data.tools.push('linux-exploit-suggester', 'gcc', 'dirty cow exploit', 'kernel exploit database');
    data.challenges.push('Identify kernel version', 'Find applicable kernel exploits', 'Compile and execute kernel exploits');
    data.techniques.push('kernel exploitation', 'dirty cow', 'local privilege escalation', 'exploit compilation');
  }

  // Metasploit & Exploitation
  if (lowerSlug.includes('metasploit') || lowerSlug.includes('msf')) {
    data.description = 'Master Metasploit for exploitation, payload generation, and post-exploitation activities.';
    data.learningObjectives.push('Metasploit framework architecture', 'Module selection and usage', 'Payload generation with msfvenom', 'Meterpreter commands', 'Post-exploitation techniques');
    data.tools.push('metasploit', 'msfconsole', 'msfvenom', 'meterpreter', 'armitage', 'searchsploit');
    data.challenges.push('Use Metasploit to exploit targets', 'Generate custom payloads', 'Perform post-exploitation', 'Pivot through networks');
    data.techniques.push('exploitation', 'payload generation', 'post-exploitation', 'pivoting', 'lateral movement', 'privilege escalation');
  }

  if (lowerSlug.includes('meterpreter')) {
    data.description = 'Leverage Meterpreter for advanced post-exploitation, pivoting, and credential dumping.';
    data.learningObjectives.push('Meterpreter architecture', 'Advanced Meterpreter commands', 'Network pivoting', 'Persistence mechanisms');
    data.tools.push('meterpreter', 'metasploit', 'mimikatz', 'autoroute');
    data.challenges.push('Establish Meterpreter sessions', 'Pivot through compromised systems', 'Dump credentials', 'Establish persistence');
    data.techniques.push('meterpreter', 'pivoting', 'port forwarding', 'credential dumping', 'persistence');
  }

  // Forensics
  if (categories.includes('Forensics') || lowerSlug.includes('forensic')) {
    data.description = 'Analyze digital evidence from disk images, memory dumps, and network captures to reconstruct security incidents.';
    data.learningObjectives.push('Digital forensics fundamentals', 'Chain of custody', 'Evidence acquisition', 'Forensic analysis techniques', 'Timeline analysis');
    data.tools.push('autopsy', 'volatility', 'wireshark', 'strings', 'exiftool', 'foremost', 'binwalk', 'ftk imager');
    data.challenges.push('Analyze forensic artifacts', 'Recover deleted data', 'Construct timeline of events', 'Identify indicators of compromise');
    data.techniques.push('disk forensics', 'memory forensics', 'network forensics', 'file carving', 'timeline analysis', 'metadata extraction');
  }

  if (lowerSlug.includes('memory') || lowerSlug.includes('volatility')) {
    data.description = 'Analyze RAM dumps with Volatility to extract credentials, identify malware, and investigate processes.';
    data.learningObjectives.push('Memory forensics concepts', 'Volatility framework usage', 'Process analysis', 'Malware detection in memory');
    data.tools.push('volatility', 'volatility3', 'rekall', 'redline');
    data.challenges.push('Analyze memory dumps', 'Extract credentials from memory', 'Identify malicious processes', 'Recover deleted artifacts');
    data.techniques.push('memory analysis', 'process inspection', 'dll injection detection', 'credential extraction', 'malware identification');
  }

  if (lowerSlug.includes('wireshark') || lowerSlug.includes('packet') || lowerSlug.includes('pcap')) {
    data.description = 'Analyze network traffic with Wireshark to identify malicious activity and extract files from packet captures.';
    data.learningObjectives.push('Network protocol analysis', 'Wireshark filter syntax', 'Traffic pattern recognition', 'Malicious traffic identification');
    data.tools.push('wireshark', 'tshark', 'tcpdump', 'networkminer', 'zeek');
    data.challenges.push('Analyze network traffic', 'Identify suspicious activity', 'Extract files from packet captures', 'Reconstruct network sessions');
    data.techniques.push('packet analysis', 'protocol dissection', 'network forensics', 'traffic filtering', 'session reconstruction');
  }

  if (lowerSlug.includes('autopsy')) {
    data.description = 'Perform disk forensics using Autopsy to recover deleted files and analyze file system artifacts.';
    data.learningObjectives.push('Disk forensics fundamentals', 'Autopsy platform usage', 'File system analysis', 'Artifact extraction');
    data.tools.push('autopsy', 'sleuthkit', 'ftk imager');
    data.challenges.push('Analyze disk images', 'Recover deleted files', 'Extract user activity artifacts', 'Generate forensic reports');
    data.techniques.push('disk forensics', 'file system analysis', 'deleted file recovery', 'artifact extraction');
  }

  // Malware Analysis
  if (categories.includes('Malware Analysis') || lowerSlug.includes('malware')) {
    data.description = 'Reverse engineer malicious software through static and dynamic analysis to extract IOCs and understand behavior.';
    data.learningObjectives.push('Malware analysis methodologies', 'Static analysis techniques', 'Dynamic analysis and sandboxing', 'Reverse engineering fundamentals', 'IOC extraction');
    data.tools.push('ghidra', 'ida pro', 'x64dbg', 'pestudio', 'remnux', 'cuckoo sandbox', 'any.run', 'procmon');
    data.challenges.push('Analyze malware samples', 'Identify malicious behavior', 'Extract indicators of compromise', 'Reverse engineer malware functionality');
    data.techniques.push('static analysis', 'dynamic analysis', 'reverse engineering', 'behavioral analysis', 'code deobfuscation');
  }

  if (lowerSlug.includes('reverse') || lowerSlug.includes('ghidra') || lowerSlug.includes('ida')) {
    data.description = 'Reverse engineer binaries using Ghidra and IDA Pro to understand program logic and identify vulnerabilities.';
    data.learningObjectives.push('Reverse engineering fundamentals', 'Assembly language analysis', 'Decompiler usage', 'Binary patching', 'Anti-reversing techniques');
    data.tools.push('ghidra', 'ida pro', 'radare2', 'binary ninja', 'gdb', 'x64dbg', 'ollydbg');
    data.challenges.push('Reverse engineer binaries', 'Understand program flow', 'Identify vulnerabilities', 'Bypass security mechanisms');
    data.techniques.push('reverse engineering', 'assembly analysis', 'decompilation', 'binary patching', 'anti-debugging bypass');
  }

  if (lowerSlug.includes('buffer') || lowerSlug.includes('overflow')) {
    data.description = 'Exploit buffer overflow vulnerabilities to achieve code execution and bypass modern protections like ASLR and DEP.';
    data.learningObjectives.push('Buffer overflow fundamentals', 'Stack vs heap overflows', 'Shellcode development', 'Exploit mitigation bypass', 'Return-oriented programming');
    data.tools.push('gdb', 'peda', 'pwndbg', 'ghidra', 'pattern_create', 'msfvenom', 'radare2');
    data.challenges.push('Identify buffer overflow vulnerabilities', 'Control execution flow', 'Develop working exploits', 'Bypass ASLR and DEP');
    data.techniques.push('buffer overflow', 'stack smashing', 'heap overflow', 'rop chains', 'shellcode injection', 'aslr bypass', 'dep bypass');
  }

  // Cryptography
  if (categories.includes('Cryptography') || lowerSlug.includes('crypto') || lowerSlug.includes('encryption')) {
    data.description = 'Break weak encryption and crack password hashes using cryptanalysis techniques.';
    data.learningObjectives.push('Cryptography fundamentals', 'Common crypto weaknesses', 'Hash cracking techniques', 'Encryption attacks', 'PKI vulnerabilities');
    data.tools.push('hashcat', 'john the ripper', 'cyberchef', 'openssl', 'hashid', 'rsatool', 'featherduster');
    data.challenges.push('Identify encryption algorithms', 'Break weak cryptography', 'Crack password hashes', 'Exploit crypto misimplementations');
    data.techniques.push('hash cracking', 'encryption analysis', 'cryptanalysis', 'known plaintext attack', 'padding oracle', 'ecb detection');
  }

  if (lowerSlug.includes('hash') || lowerSlug.includes('crack')) {
    data.description = 'Crack password hashes using wordlist attacks, rules, and GPU acceleration with Hashcat and John the Ripper.';
    data.learningObjectives.push('Hash algorithm identification', 'Wordlist-based attacks', 'Rule-based cracking', 'Hybrid attacks', 'GPU acceleration');
    data.tools.push('hashcat', 'john the ripper', 'hashid', 'crackstation', 'ophcrack');
    data.challenges.push('Identify hash types', 'Crack various password hashes', 'Create custom wordlists', 'Optimize cracking performance');
    data.techniques.push('hash cracking', 'wordlist attacks', 'rule-based attacks', 'rainbow tables', 'gpu cracking', 'mask attacks');
  }

  if (lowerSlug.includes('rsa')) {
    data.description = 'Exploit weak RSA implementations through factorization attacks and small exponent vulnerabilities.';
    data.learningObjectives.push('RSA algorithm fundamentals', 'Common RSA weaknesses', 'Factorization attacks', 'Small exponent attacks');
    data.tools.push('rsatool', 'python', 'yafu', 'msieve', 'sage');
    data.challenges.push('Factor weak RSA moduli', 'Exploit small public exponents', 'Perform chosen ciphertext attacks');
    data.techniques.push('rsa cryptanalysis', 'factorization', 'wieners attack', 'common modulus attack', 'low exponent attack');
  }

  // Blue Team & SOC
  if (categories.includes('Blue Team') || lowerSlug.includes('soc') || lowerSlug.includes('splunk') || lowerSlug.includes('elk')) {
    data.description = 'Analyze security logs with SIEM platforms to detect threats and respond to security incidents.';
    data.learningObjectives.push('Security monitoring fundamentals', 'SIEM platform usage', 'Threat hunting techniques', 'Incident response procedures', 'Alert tuning and correlation');
    data.tools.push('splunk', 'elastic stack', 'kibana', 'sigma', 'wireshark', 'suricata', 'zeek', 'osquery');
    data.challenges.push('Analyze security logs', 'Detect malicious activity', 'Investigate security incidents', 'Create detection rules');
    data.techniques.push('log analysis', 'threat hunting', 'incident response', 'siem querying', 'alert correlation', 'ioc identification');
  }

  if (lowerSlug.includes('threat') && lowerSlug.includes('hunt')) {
    data.description = 'Proactively hunt for advanced threats through hypothesis-driven investigation and behavioral analysis.';
    data.learningObjectives.push('Threat hunting methodologies', 'Hypothesis development', 'Data analysis techniques', 'TTP identification');
    data.tools.push('splunk', 'elk', 'velociraptor', 'osquery', 'sysmon');
    data.challenges.push('Develop hunting hypotheses', 'Analyze system telemetry', 'Identify advanced threats', 'Document findings');
    data.techniques.push('threat hunting', 'hypothesis testing', 'behavioral analysis', 'anomaly detection');
  }

  if (lowerSlug.includes('incident') && lowerSlug.includes('response')) {
    data.description = 'Respond to security incidents through evidence collection, threat containment, and root cause analysis.';
    data.learningObjectives.push('Incident response lifecycle', 'Evidence preservation', 'Containment strategies', 'Root cause analysis');
    data.tools.push('forensic toolkit', 'volatility', 'autopsy', 'wireshark', 'sysinternals');
    data.challenges.push('Respond to security incidents', 'Collect and preserve evidence', 'Contain threats', 'Perform root cause analysis');
    data.techniques.push('incident response', 'forensic investigation', 'containment', 'eradication', 'recovery');
  }

  // OSINT
  if (categories.includes('OSINT') || lowerSlug.includes('osint')) {
    data.description = 'Gather and correlate open source intelligence from public sources using advanced search techniques.';
    data.learningObjectives.push('OSINT fundamentals', 'Search engine techniques', 'Social media investigation', 'Domain reconnaissance', 'Operational security');
    data.tools.push('maltego', 'theharvester', 'shodan', 'censys', 'recon-ng', 'spiderfoot', 'google dorks');
    data.challenges.push('Gather OSINT information', 'Correlate data from multiple sources', 'Maintain operational security', 'Document findings');
    data.techniques.push('osint', 'google dorking', 'social media analysis', 'domain reconnaissance', 'people search', 'image analysis');
  }

  if (lowerSlug.includes('shodan')) {
    data.description = 'Discover internet-exposed devices and services using Shodan search queries to identify vulnerabilities.';
    data.learningObjectives.push('Shodan search syntax', 'Device fingerprinting', 'Vulnerability discovery', 'API usage');
    data.tools.push('shodan', 'shodan cli', 'censys');
    data.challenges.push('Discover vulnerable devices', 'Create custom search queries', 'Analyze exposure risks');
    data.techniques.push('shodan querying', 'internet scanning', 'device enumeration', 'vulnerability discovery');
  }

  // Web Application Testing
  if (lowerSlug.includes('burp')) {
    data.description = 'Test web applications with Burp Suite through proxy interception, automated scanning, and custom extensions.';
    data.learningObjectives.push('Burp Suite architecture', 'Proxy configuration and usage', 'Intruder attack types', 'Scanner usage', 'Extension development');
    data.tools.push('burp suite professional', 'burp extensions', 'burp collaborator');
    data.challenges.push('Intercept and modify requests', 'Perform automated attacks', 'Develop custom extensions', 'Exploit web vulnerabilities');
    data.techniques.push('proxy interception', 'request manipulation', 'automated scanning', 'fuzzing', 'session handling');
  }

  if (lowerSlug.includes('api')) {
    data.description = 'Test REST and GraphQL APIs for authentication bypass, authorization flaws, and injection vulnerabilities.';
    data.learningObjectives.push('API security fundamentals', 'Authentication testing', 'Authorization bypass', 'Rate limiting abuse', 'Mass assignment');
    data.tools.push('postman', 'burp suite', 'curl', 'jwt_tool', 'graphql voyager');
    data.challenges.push('Test API authentication', 'Exploit authorization flaws', 'Abuse rate limiting', 'Exploit mass assignment');
    data.techniques.push('api testing', 'authentication bypass', 'authorization abuse', 'graphql injection', 'jwt attacks');
  }

  if (lowerSlug.includes('jwt') || lowerSlug.includes('token')) {
    data.description = 'Exploit JSON Web Token vulnerabilities through algorithm confusion and signature bypass attacks.';
    data.learningObjectives.push('JWT structure and standards', 'Algorithm confusion attacks', 'Token manipulation', 'Signature bypass');
    data.tools.push('jwt_tool', 'burp suite', 'cyberchef');
    data.challenges.push('Decode and analyze JWTs', 'Exploit algorithm confusion', 'Bypass signature verification');
    data.techniques.push('jwt manipulation', 'algorithm confusion', 'none attack', 'weak secret', 'kid injection');
  }

  // Container & Cloud Security
  if (lowerSlug.includes('docker') || lowerSlug.includes('container')) {
    data.description = 'Exploit Docker containers through escape techniques and misconfiguration abuse to gain host access.';
    data.learningObjectives.push('Container security fundamentals', 'Docker architecture', 'Container escape techniques', 'Image vulnerability analysis');
    data.tools.push('docker', 'docker-compose', 'trivy', 'clair', 'docker-bench-security');
    data.challenges.push('Exploit container misconfigurations', 'Escape Docker containers', 'Analyze container images', 'Exploit orchestration platforms');
    data.techniques.push('container escape', 'docker exploitation', 'privilege escalation', 'image analysis', 'registry exploitation');
  }

  if (lowerSlug.includes('kubernetes') || lowerSlug.includes('k8s')) {
    data.description = 'Compromise Kubernetes clusters through RBAC abuse, pod escape, and API server exploitation.';
    data.learningObjectives.push('Kubernetes architecture', 'Pod security policies', 'RBAC exploitation', 'API server attacks');
    data.tools.push('kubectl', 'kubeletctl', 'kube-hunter', 'kubesploit');
    data.challenges.push('Enumerate Kubernetes clusters', 'Exploit RBAC misconfigurations', 'Escape pod restrictions', 'Compromise cluster');
    data.techniques.push('kubernetes exploitation', 'rbac abuse', 'pod escape', 'api exploitation', 'service account abuse');
  }

  if (lowerSlug.includes('cloud') || lowerSlug.includes('aws') || lowerSlug.includes('azure')) {
    data.description = 'Exploit cloud misconfigurations and IAM flaws to escalate privileges and access sensitive resources.';
    data.learningObjectives.push('Cloud security fundamentals', 'IAM exploitation', 'Storage misconfiguration', 'Serverless security');
    data.tools.push('aws cli', 'azure cli', 'pacu', 'prowler', 'scoutsuite', 'cloudsploit');
    data.challenges.push('Enumerate cloud resources', 'Exploit IAM misconfigurations', 'Access misconfigured storage', 'Compromise cloud infrastructure');
    data.techniques.push('cloud enumeration', 'iam exploitation', 'metadata service abuse', 'privilege escalation', 'lateral movement');
  }

  // CTF & Challenges
  if (lowerSlug.includes('ctf') || lowerSlug.includes('challenge')) {
    data.description = 'Solve multi-domain CTF challenges by chaining vulnerabilities and thinking creatively to capture flags.';
    data.learningObjectives.push('CTF methodologies', 'Multi-domain problem solving', 'Tool selection and usage', 'Time management in CTFs');
    data.tools.push('various ctf tools', 'python', 'bash', 'burp suite', 'ghidra');
    data.challenges.push('Solve diverse security challenges', 'Find hidden flags', 'Chain multiple vulnerabilities', 'Think creatively');
    data.techniques.push('ctf techniques', 'flag hunting', 'multi-stage exploitation', 'lateral thinking');
  }

  if (lowerSlug.includes('steganography') || lowerSlug.includes('stego')) {
    data.description = 'Extract hidden data from images, audio files, and documents using steganography analysis techniques.';
    data.learningObjectives.push('Steganography fundamentals', 'Image analysis', 'Audio steganography', 'Text-based hiding');
    data.tools.push('steghide', 'stegsolve', 'binwalk', 'exiftool', 'zsteg', 'sonic visualizer');
    data.challenges.push('Extract hidden data from images', 'Analyze audio files', 'Detect steganographic content');
    data.techniques.push('steganography', 'lsb analysis', 'metadata extraction', 'file carving', 'spectral analysis');
  }

  // Default for unrecognized patterns
  if (data.learningObjectives.length === 0) {
    data.description = `Practical cybersecurity training covering ${title} with hands-on challenges and real-world scenarios.`;
    data.learningObjectives.push('Practical cybersecurity skills', 'Problem-solving techniques', 'Security tool proficiency');
    data.tools.push('nmap', 'burp suite', 'metasploit');
    data.challenges.push('Complete room objectives', 'Find all flags', 'Document methodology');
    data.techniques.push('enumeration', 'exploitation', 'post-exploitation');
  }

  // Remove duplicates
  data.learningObjectives = [...new Set(data.learningObjectives)];
  data.tools = [...new Set(data.tools)];
  data.challenges = [...new Set(data.challenges)];
  data.techniques = [...new Set(data.techniques)];

  // Generate technical summary
  data.technicalSummary = generateTechnicalSummary(slug, title, categories, data);

  return data;
}

async function enrichAllRooms() {
  try {
    console.log('🔄 Connecting to database...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tryhackme-dashboard');
    console.log('✅ Connected to database');

    console.log('🔄 Fetching all rooms...');
    const rooms = await Room.find({});
    console.log(`📊 Found ${rooms.length} rooms to enrich`);

    let enriched = 0;

    for (const room of rooms) {
      const enrichmentData = enrichRoomData(room.slug, room.title, room.categories);

      await Room.updateOne(
        { _id: room._id },
        {
          $set: {
            learningObjectives: enrichmentData.learningObjectives,
            tools: enrichmentData.tools,
            challenges: enrichmentData.challenges,
            techniques: enrichmentData.techniques,
            description: enrichmentData.description,
            scrapedData: {
              summary: enrichmentData.technicalSummary,
              keySteps: [],
              commonPitfalls: [],
            },
            lastUpdated: new Date(),
          },
        }
      );
      enriched++;

      if (enriched % 50 === 0) {
        console.log(`📊 Progress: ${enriched}/${rooms.length} rooms enriched`);
      }
    }

    console.log('\n✅ Enrichment complete!');
    console.log(`📊 Total enriched: ${enriched} rooms`);

    await mongoose.disconnect();
    console.log('👋 Disconnected from database');
  } catch (error) {
    console.error('❌ Fatal error:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  enrichAllRooms();
}

export default enrichAllRooms;
