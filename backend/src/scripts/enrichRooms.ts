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

// Generate comprehensive technical summary
function generateTechnicalSummary(slug: string, title: string, categories: string[], data: EnrichmentData): string {
  const parts: string[] = [];

  // Introduction
  parts.push(`## ${title}\n`);
  parts.push(`**Room Type:** ${categories.join(', ') || 'General'}\n`);
  parts.push(`**Difficulty Assessment:** This room provides hands-on experience with ${data.techniques.join(', ') || 'various cybersecurity techniques'}.\n`);

  // Overview
  parts.push(`\n### Overview\n`);
  parts.push(data.description + '\n');

  // Learning Path
  if (data.learningObjectives.length > 0) {
    parts.push(`\n### Learning Objectives\n`);
    data.learningObjectives.forEach((obj, i) => {
      parts.push(`${i + 1}. **${obj}**: Understanding the core concepts and practical application of this technique is essential for modern cybersecurity professionals. This objective covers both theoretical knowledge and hands-on exploitation techniques.\n`);
    });
  }

  // Technical Methodology
  parts.push(`\n### Technical Methodology\n`);
  parts.push(`This room follows a structured penetration testing methodology:\n`);
  parts.push(`\n**Phase 1: Reconnaissance**\n`);
  parts.push(`Begin with thorough enumeration of the target system. Utilize tools such as ${data.tools.slice(0, 3).join(', ')} to gather information about open ports, running services, and potential vulnerabilities. Document all findings systematically.\n`);

  parts.push(`\n**Phase 2: Scanning & Enumeration**\n`);
  parts.push(`Deep dive into service enumeration. Each discovered service should be thoroughly investigated for version information, misconfigurations, and known vulnerabilities. Pay special attention to ${data.techniques[0] || 'common attack vectors'}.\n`);

  parts.push(`\n**Phase 3: Exploitation**\n`);
  parts.push(`Based on the enumeration phase, identify and exploit vulnerabilities. ${data.challenges[0] || 'The primary challenge involves gaining initial access to the system'}. Consider multiple attack vectors and document each attempt.\n`);

  parts.push(`\n**Phase 4: Post-Exploitation**\n`);
  parts.push(`Once initial access is gained, focus on privilege escalation, persistence mechanisms, and lateral movement. Understanding the system architecture is crucial for identifying privilege escalation vectors.\n`);

  // Tools Deep Dive
  if (data.tools.length > 0) {
    parts.push(`\n### Required Tools & Technologies\n`);
    data.tools.forEach(tool => {
      parts.push(`\n**${tool.toUpperCase()}**\n`);
      parts.push(`This tool plays a crucial role in the exploitation process. Familiarize yourself with its key features, command-line options, and integration with other security tools. Practice using ${tool} in isolated environments before attempting real-world scenarios.\n`);
    });
  }

  // Techniques Explained
  if (data.techniques.length > 0) {
    parts.push(`\n### Attack Techniques & Vectors\n`);
    data.techniques.forEach(technique => {
      parts.push(`\n**${technique.toUpperCase()}**\n`);
      parts.push(`Understanding ${technique} requires both theoretical knowledge and practical application. This technique is commonly found in real-world scenarios and represents a critical skill for security professionals. The exploitation process involves identifying vulnerable components, crafting appropriate payloads, and executing the attack while maintaining operational security.\n`);
    });
  }

  // Challenges Breakdown
  if (data.challenges.length > 0) {
    parts.push(`\n### Challenge Breakdown\n`);
    data.challenges.forEach((challenge, i) => {
      parts.push(`\n**Challenge ${i + 1}: ${challenge}**\n`);
      parts.push(`This challenge tests your understanding of the concepts covered in this room. Approach it systematically, document your findings, and don't hesitate to research unfamiliar concepts. The solution requires creative thinking and thorough enumeration.\n`);
    });
  }

  // Advanced Concepts
  parts.push(`\n### Advanced Concepts & Considerations\n`);
  parts.push(`**Defense Evasion:** Understanding how to bypass security controls is crucial. This includes evading antivirus, IDS/IPS, firewalls, and application whitelisting.\n`);
  parts.push(`**Persistence Mechanisms:** Explore various methods to maintain access to compromised systems. Consider both obvious and subtle persistence techniques.\n`);
  parts.push(`**Operational Security:** Always maintain operational security during penetration testing activities. This includes covering tracks, using encryption, and avoiding detection.\n`);

  // Real-World Applications
  parts.push(`\n### Real-World Applications\n`);
  parts.push(`The skills learned in this room have direct applications in:\n`);
  parts.push(`- Penetration Testing Engagements: Identifying and exploiting similar vulnerabilities in production environments\n`);
  parts.push(`- Red Team Operations: Simulating advanced persistent threats and sophisticated attack scenarios\n`);
  parts.push(`- Security Research: Discovering new vulnerabilities and developing proof-of-concept exploits\n`);
  parts.push(`- Blue Team Defense: Understanding attacker methodologies to build better defensive strategies\n`);

  // Additional Resources
  parts.push(`\n### Further Learning Resources\n`);
  parts.push(`To deepen your understanding:\n`);
  parts.push(`1. Review official documentation for all tools used\n`);
  parts.push(`2. Study related CVEs and vulnerability disclosures\n`);
  parts.push(`3. Practice in isolated lab environments\n`);
  parts.push(`4. Engage with the cybersecurity community\n`);
  parts.push(`5. Document your methodology for future reference\n`);

  // Conclusion
  parts.push(`\n### Conclusion\n`);
  parts.push(`This room provides comprehensive training in ${categories[0] || 'cybersecurity'} concepts. Mastery of these skills requires practice, patience, and continuous learning. Apply the knowledge gained here responsibly and ethically in authorized security testing scenarios.\n`);

  return parts.join('\n');
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
    data.description = 'Master SQL injection vulnerabilities through hands-on exploitation. Learn to identify injection points, bypass authentication, extract sensitive data, and understand database security fundamentals.';
    data.learningObjectives.push('SQL injection fundamentals and advanced techniques', 'Database enumeration and exploitation', 'Bypassing WAF and input validation', 'Automated vs manual injection approaches');
    data.tools.push('sqlmap', 'burp suite', 'browser devtools', 'curl', 'python');
    data.challenges.push('Identify and exploit SQL injection vulnerabilities', 'Extract database credentials and sensitive information', 'Bypass authentication using SQL injection', 'Achieve remote code execution via SQL injection');
    data.techniques.push('union-based sql injection', 'error-based injection', 'blind sql injection', 'time-based sql injection', 'out-of-band sql injection');
  }

  if (lowerSlug.includes('xss') || lowerSlug.includes('cross-site')) {
    data.description = 'Explore Cross-Site Scripting (XSS) vulnerabilities from both offensive and defensive perspectives. Learn reflected, stored, and DOM-based XSS exploitation techniques.';
    data.learningObjectives.push('Understanding XSS attack vectors', 'Client-side security principles', 'Cookie theft and session hijacking', 'XSS filter bypass techniques');
    data.tools.push('burp suite', 'browser devtools', 'xss hunter', 'beef framework', 'zaproxy');
    data.challenges.push('Exploit reflected XSS vulnerabilities', 'Store malicious payloads for persistent XSS', 'Bypass XSS filters and sanitization', 'Steal session cookies using XSS');
    data.techniques.push('reflected xss', 'stored xss', 'dom-based xss', 'filter evasion', 'payload obfuscation');
  }

  if (lowerSlug.includes('owasp')) {
    data.description = 'Comprehensive coverage of OWASP Top 10 vulnerabilities. Learn to identify, exploit, and remediate the most critical web application security risks.';
    data.learningObjectives.push('OWASP Top 10 vulnerability categories', 'Web application security fundamentals', 'Secure coding practices', 'Security testing methodologies');
    data.tools.push('burp suite', 'owasp zap', 'nikto', 'dirb', 'wfuzz', 'sqlmap');
    data.challenges.push('Identify and exploit injection flaws', 'Bypass broken authentication mechanisms', 'Exploit sensitive data exposure', 'Leverage security misconfigurations');
    data.techniques.push('injection attacks', 'broken authentication', 'sensitive data exposure', 'xxe', 'broken access control', 'security misconfiguration');
  }

  if (lowerSlug.includes('lfi') || lowerSlug.includes('rfi') || lowerSlug.includes('file-inclusion')) {
    data.description = 'Deep dive into Local and Remote File Inclusion vulnerabilities. Master path traversal, log poisoning, and achieving remote code execution through file inclusion flaws.';
    data.learningObjectives.push('File inclusion vulnerability identification', 'Path traversal attack techniques', 'Log poisoning for RCE', 'PHP wrapper exploitation');
    data.tools.push('burp suite', 'curl', 'netcat', 'ffuf', 'wfuzz');
    data.challenges.push('Exploit LFI to read sensitive files', 'Achieve remote code execution via log poisoning', 'Use PHP wrappers for exploitation', 'Bypass LFI filters and restrictions');
    data.techniques.push('local file inclusion', 'remote file inclusion', 'path traversal', 'log poisoning', 'php wrapper exploitation', 'null byte injection');
  }

  if (lowerSlug.includes('ssrf')) {
    data.description = 'Learn Server-Side Request Forgery exploitation techniques. Understand how to abuse SSRF to access internal resources, cloud metadata, and bypass network restrictions.';
    data.learningObjectives.push('SSRF vulnerability identification', 'Internal network exploitation', 'Cloud metadata service abuse', 'SSRF defense bypass');
    data.tools.push('burp suite', 'curl', 'ngrok', 'collaborator');
    data.challenges.push('Exploit SSRF to access internal services', 'Retrieve cloud instance metadata', 'Port scanning via SSRF', 'Bypass SSRF protections');
    data.techniques.push('ssrf', 'internal port scanning', 'cloud metadata exploitation', 'filter bypass', 'dns rebinding');
  }

  if (lowerSlug.includes('csrf')) {
    data.description = 'Master Cross-Site Request Forgery attacks and defenses. Learn to craft CSRF exploits, bypass token validation, and understand anti-CSRF mechanisms.';
    data.learningObjectives.push('CSRF attack fundamentals', 'Token validation bypass', 'CSRF prevention mechanisms', 'Advanced CSRF exploitation');
    data.tools.push('burp suite', 'browser', 'csrf poc generator');
    data.challenges.push('Craft CSRF exploits for state-changing operations', 'Bypass CSRF token validation', 'Chain CSRF with other vulnerabilities');
    data.techniques.push('csrf', 'token bypass', 'referrer spoofing', 'same-site cookie bypass');
  }

  if (lowerSlug.includes('xxe')) {
    data.description = 'Explore XML External Entity (XXE) injection vulnerabilities. Learn to exploit XXE for file disclosure, SSRF, denial of service, and remote code execution.';
    data.learningObjectives.push('XML parsing vulnerabilities', 'XXE exploitation techniques', 'Out-of-band XXE', 'Blind XXE detection');
    data.tools.push('burp suite', 'xxe injector', 'collaborator');
    data.challenges.push('Exploit XXE to read local files', 'Use XXE for SSRF attacks', 'Perform denial of service via XXE');
    data.techniques.push('xxe injection', 'out-of-band xxe', 'blind xxe', 'parameter entities', 'xxe to rce');
  }

  if (lowerSlug.includes('deserialization') || lowerSlug.includes('pickle')) {
    data.description = 'Understand insecure deserialization vulnerabilities across multiple programming languages. Learn to craft malicious serialized objects for remote code execution.';
    data.learningObjectives.push('Deserialization vulnerability concepts', 'Object injection attacks', 'Gadget chain construction', 'Language-specific deserialization');
    data.tools.push('ysoserial', 'burp suite', 'java decompiler', 'python pickle');
    data.challenges.push('Identify deserialization points', 'Craft malicious serialized objects', 'Achieve RCE via deserialization');
    data.techniques.push('insecure deserialization', 'object injection', 'gadget chains', 'java deserialization', 'python pickle exploitation');
  }

  // Network & Enumeration
  if (lowerSlug.includes('nmap') || lowerSlug.includes('scan')) {
    data.description = 'Master network scanning and enumeration with Nmap. Learn port scanning techniques, service detection, OS fingerprinting, and NSE scripting.';
    data.learningObjectives.push('Network scanning methodologies', 'Service version detection', 'OS fingerprinting techniques', 'NSE script usage', 'Firewall evasion');
    data.tools.push('nmap', 'masscan', 'rustscan', 'unicornscan', 'zmap');
    data.challenges.push('Perform comprehensive port scans', 'Identify services and versions', 'Detect operating system', 'Use NSE scripts for vulnerability detection');
    data.techniques.push('syn scanning', 'tcp connect scanning', 'udp scanning', 'service enumeration', 'os detection', 'firewall evasion');
  }

  if (lowerSlug.includes('enum') || lowerSlug.includes('recon')) {
    data.description = 'Comprehensive enumeration and reconnaissance training. Learn information gathering techniques for networks, web applications, and system services.';
    data.learningObjectives.push('Systematic enumeration methodology', 'Service-specific enumeration', 'OSINT techniques', 'Automated reconnaissance');
    data.tools.push('nmap', 'gobuster', 'enum4linux', 'ldapsearch', 'smbclient', 'snmpwalk', 'dig', 'theHarvester');
    data.challenges.push('Enumerate all accessible services', 'Gather user and system information', 'Identify potential attack vectors');
    data.techniques.push('port scanning', 'service enumeration', 'smb enumeration', 'ldap enumeration', 'dns enumeration', 'web enumeration');
  }

  if (lowerSlug.includes('gobuster') || lowerSlug.includes('dirb') || lowerSlug.includes('directory')) {
    data.description = 'Learn web content discovery techniques using various fuzzing tools. Master directory brute-forcing, virtual host discovery, and file enumeration.';
    data.learningObjectives.push('Directory brute-forcing techniques', 'Custom wordlist creation', 'Recursive enumeration', 'Virtual host discovery');
    data.tools.push('gobuster', 'dirb', 'ffuf', 'wfuzz', 'dirbuster', 'feroxbuster');
    data.challenges.push('Discover hidden directories and files', 'Enumerate virtual hosts', 'Find backup files and sensitive data');
    data.techniques.push('directory brute-forcing', 'content discovery', 'fuzzing', 'wordlist optimization');
  }

  // Windows Exploitation
  if (categories.includes('Windows') || lowerSlug.includes('windows')) {
    data.description = 'Comprehensive Windows exploitation training covering common vulnerabilities, misconfigurations, and attack techniques specific to Windows environments.';
    data.learningObjectives.push('Windows architecture and security', 'Common Windows vulnerabilities', 'Privilege escalation techniques', 'Post-exploitation strategies');
    data.tools.push('nmap', 'metasploit', 'powershell', 'mimikatz', 'bloodhound', 'sharphound', 'winpeas', 'accesschk');
    data.challenges.push('Exploit Windows vulnerabilities', 'Escalate to SYSTEM privileges', 'Extract credentials from memory', 'Achieve persistence');
    data.techniques.push('windows exploitation', 'privilege escalation', 'credential dumping', 'lateral movement', 'persistence mechanisms');
  }

  if (lowerSlug.includes('active-directory') || lowerSlug.includes('ad-')) {
    data.description = 'Master Active Directory penetration testing. Learn AD enumeration, Kerberos attacks, delegation abuse, and path to Domain Admin.';
    data.learningObjectives.push('Active Directory fundamentals', 'AD enumeration techniques', 'Kerberos authentication attacks', 'Domain privilege escalation', 'AD persistence mechanisms');
    data.tools.push('bloodhound', 'sharphound', 'powerview', 'rubeus', 'mimikatz', 'impacket', 'crackmapexec', 'kerbrute', 'ldapdomaindump');
    data.challenges.push('Enumerate Active Directory environment', 'Perform Kerberoasting attack', 'Abuse delegation vulnerabilities', 'Achieve Domain Admin privileges', 'Implement persistence in AD');
    data.techniques.push('kerberoasting', 'asreproasting', 'pass-the-hash', 'pass-the-ticket', 'golden ticket', 'silver ticket', 'dcsync', 'zerologon', 'printnightmare');
  }

  if (lowerSlug.includes('powershell')) {
    data.description = 'Learn PowerShell for offensive security operations. Master PowerShell scripting, obfuscation, AMSI bypass, and post-exploitation frameworks.';
    data.learningObjectives.push('PowerShell scripting for pentesting', 'PowerShell obfuscation techniques', 'AMSI and logging bypass', 'PowerShell exploitation frameworks');
    data.tools.push('powershell', 'powerview', 'powerup', 'empire', 'powersploit', 'nishang', 'invoke-obfuscation');
    data.challenges.push('Use PowerShell for system enumeration', 'Bypass AMSI and script block logging', 'Exploit using PowerShell frameworks');
    data.techniques.push('powershell scripting', 'amsi bypass', 'obfuscation', 'fileless malware', 'powershell exploitation');
  }

  if (lowerSlug.includes('bloodhound')) {
    data.description = 'Master BloodHound for Active Directory attack path analysis. Learn graph theory application to AD security and automated privilege escalation path discovery.';
    data.learningObjectives.push('BloodHound data collection', 'Graph database querying', 'Attack path identification', 'Custom Cypher queries');
    data.tools.push('bloodhound', 'sharphound', 'azurehound', 'neo4j');
    data.challenges.push('Collect and analyze AD data', 'Identify paths to Domain Admin', 'Find exploitable ACL misconfigurations');
    data.techniques.push('graph theory', 'acl exploitation', 'delegation abuse', 'group policy abuse');
  }

  if (lowerSlug.includes('eternal') || lowerSlug.includes('blue')) {
    data.description = 'Exploit the EternalBlue vulnerability (MS17-010). Understand SMB vulnerabilities, exploit development, and Metasploit module usage.';
    data.learningObjectives.push('SMB protocol vulnerabilities', 'EternalBlue exploitation', 'Metasploit framework usage', 'DoublePulsar backdoor');
    data.tools.push('nmap', 'metasploit', 'smbclient', 'auxiliary modules');
    data.challenges.push('Identify vulnerable SMB services', 'Exploit MS17-010', 'Gain remote code execution', 'Post-exploitation activities');
    data.techniques.push('smb exploitation', 'eternalblue', 'buffer overflow', 'remote code execution');
  }

  // Linux Exploitation
  if (categories.includes('Linux') || lowerSlug.includes('linux')) {
    data.description = 'Comprehensive Linux exploitation and privilege escalation training. Master Linux security concepts, common misconfigurations, and privilege escalation vectors.';
    data.learningObjectives.push('Linux security architecture', 'File system permissions', 'Privilege escalation methodologies', 'Linux post-exploitation');
    data.tools.push('linpeas', 'linenum', 'linuxprivchecker', 'pspy', 'gtfobins', 'unix-privesc-check');
    data.challenges.push('Enumerate Linux system', 'Identify privilege escalation vectors', 'Escalate to root privileges', 'Maintain persistent access');
    data.techniques.push('suid exploitation', 'sudo abuse', 'kernel exploits', 'cron jobs', 'nfs misconfiguration', 'docker escape');
  }

  if (lowerSlug.includes('privesc') || lowerSlug.includes('privilege')) {
    data.description = 'Master privilege escalation techniques for both Linux and Windows systems. Learn systematic enumeration, vulnerability identification, and exploitation.';
    data.learningObjectives.push('Privilege escalation methodology', 'System enumeration techniques', 'Common privilege escalation vectors', 'Automated vs manual enumeration');
    data.tools.push('linpeas', 'winpeas', 'pspy', 'gtfobins', 'lolbas', 'sudo -l', 'accesschk');
    data.challenges.push('Perform thorough system enumeration', 'Identify privilege escalation paths', 'Escalate to root/administrator', 'Document exploitation process');
    data.techniques.push('privilege escalation', 'suid/sgid exploitation', 'sudo abuse', 'kernel exploits', 'scheduled tasks', 'service exploits', 'registry exploitation');
  }

  if (lowerSlug.includes('sudo')) {
    data.description = 'Exploit sudo misconfigurations for privilege escalation. Learn about GTFOBins, sudo tokens, and advanced sudo bypass techniques.';
    data.learningObjectives.push('Sudo security model', 'GTFOBins usage', 'Sudo token manipulation', 'Sudo policy analysis');
    data.tools.push('gtfobins', 'sudo', 'sudoedit');
    data.challenges.push('Identify sudo misconfigurations', 'Escalate privileges via sudo', 'Bypass sudo restrictions');
    data.techniques.push('sudo abuse', 'gtfobins', 'sudo token reuse', 'sudo policy bypass');
  }

  if (lowerSlug.includes('suid') || lowerSlug.includes('sgid')) {
    data.description = 'Exploit SUID/SGID binaries for privilege escalation. Learn to identify vulnerable binaries and abuse them for root access.';
    data.learningObjectives.push('SUID/SGID concepts', 'Binary exploitation basics', 'GTFOBins for SUID abuse', 'Custom SUID exploitation');
    data.tools.push('find', 'gtfobins', 'strings', 'ltrace', 'strace');
    data.challenges.push('Find SUID binaries', 'Exploit misconfigured SUID binaries', 'Achieve root access');
    data.techniques.push('suid exploitation', 'sgid abuse', 'binary analysis', 'path hijacking');
  }

  if (lowerSlug.includes('kernel')) {
    data.description = 'Learn kernel exploitation techniques and dirty cow exploits. Understand kernel vulnerabilities and their exploitation for privilege escalation.';
    data.learningObjectives.push('Kernel architecture basics', 'Kernel vulnerability identification', 'Kernel exploit compilation', 'Exploit stability considerations');
    data.tools.push('linux-exploit-suggester', 'gcc', 'dirty cow exploit', 'kernel exploit database');
    data.challenges.push('Identify kernel version', 'Find applicable kernel exploits', 'Compile and execute kernel exploits');
    data.techniques.push('kernel exploitation', 'dirty cow', 'local privilege escalation', 'exploit compilation');
  }

  // Metasploit & Exploitation
  if (lowerSlug.includes('metasploit') || lowerSlug.includes('msf')) {
    data.description = 'Master the Metasploit Framework for penetration testing. Learn module usage, payload generation, post-exploitation, and custom module development.';
    data.learningObjectives.push('Metasploit framework architecture', 'Module selection and usage', 'Payload generation with msfvenom', 'Meterpreter commands', 'Post-exploitation techniques');
    data.tools.push('metasploit', 'msfconsole', 'msfvenom', 'meterpreter', 'armitage', 'searchsploit');
    data.challenges.push('Use Metasploit to exploit targets', 'Generate custom payloads', 'Perform post-exploitation', 'Pivot through networks');
    data.techniques.push('exploitation', 'payload generation', 'post-exploitation', 'pivoting', 'lateral movement', 'privilege escalation');
  }

  if (lowerSlug.includes('meterpreter')) {
    data.description = 'Deep dive into Meterpreter post-exploitation framework. Master advanced Meterpreter commands, pivoting, and persistence.';
    data.learningObjectives.push('Meterpreter architecture', 'Advanced Meterpreter commands', 'Network pivoting', 'Persistence mechanisms');
    data.tools.push('meterpreter', 'metasploit', 'mimikatz', 'autoroute');
    data.challenges.push('Establish Meterpreter sessions', 'Pivot through compromised systems', 'Dump credentials', 'Establish persistence');
    data.techniques.push('meterpreter', 'pivoting', 'port forwarding', 'credential dumping', 'persistence');
  }

  // Forensics
  if (categories.includes('Forensics') || lowerSlug.includes('forensic')) {
    data.description = 'Comprehensive digital forensics training covering disk, memory, and network forensics. Learn evidence collection, analysis, and reporting.';
    data.learningObjectives.push('Digital forensics fundamentals', 'Chain of custody', 'Evidence acquisition', 'Forensic analysis techniques', 'Timeline analysis');
    data.tools.push('autopsy', 'volatility', 'wireshark', 'strings', 'exiftool', 'foremost', 'binwalk', 'ftk imager');
    data.challenges.push('Analyze forensic artifacts', 'Recover deleted data', 'Construct timeline of events', 'Identify indicators of compromise');
    data.techniques.push('disk forensics', 'memory forensics', 'network forensics', 'file carving', 'timeline analysis', 'metadata extraction');
  }

  if (lowerSlug.includes('memory') || lowerSlug.includes('volatility')) {
    data.description = 'Master memory forensics with Volatility framework. Learn RAM analysis, process investigation, and malware detection in memory dumps.';
    data.learningObjectives.push('Memory forensics concepts', 'Volatility framework usage', 'Process analysis', 'Malware detection in memory');
    data.tools.push('volatility', 'volatility3', 'rekall', 'redline');
    data.challenges.push('Analyze memory dumps', 'Extract credentials from memory', 'Identify malicious processes', 'Recover deleted artifacts');
    data.techniques.push('memory analysis', 'process inspection', 'dll injection detection', 'credential extraction', 'malware identification');
  }

  if (lowerSlug.includes('wireshark') || lowerSlug.includes('packet') || lowerSlug.includes('pcap')) {
    data.description = 'Master network traffic analysis with Wireshark. Learn packet analysis, protocol dissection, and network forensics techniques.';
    data.learningObjectives.push('Network protocol analysis', 'Wireshark filter syntax', 'Traffic pattern recognition', 'Malicious traffic identification');
    data.tools.push('wireshark', 'tshark', 'tcpdump', 'networkminer', 'zeek');
    data.challenges.push('Analyze network traffic', 'Identify suspicious activity', 'Extract files from packet captures', 'Reconstruct network sessions');
    data.techniques.push('packet analysis', 'protocol dissection', 'network forensics', 'traffic filtering', 'session reconstruction');
  }

  if (lowerSlug.includes('autopsy')) {
    data.description = 'Learn digital forensics with Autopsy. Master disk image analysis, file system forensics, and automated artifact extraction.';
    data.learningObjectives.push('Disk forensics fundamentals', 'Autopsy platform usage', 'File system analysis', 'Artifact extraction');
    data.tools.push('autopsy', 'sleuthkit', 'ftk imager');
    data.challenges.push('Analyze disk images', 'Recover deleted files', 'Extract user activity artifacts', 'Generate forensic reports');
    data.techniques.push('disk forensics', 'file system analysis', 'deleted file recovery', 'artifact extraction');
  }

  // Malware Analysis
  if (categories.includes('Malware Analysis') || lowerSlug.includes('malware')) {
    data.description = 'Comprehensive malware analysis training covering static and dynamic analysis. Learn reverse engineering, behavior analysis, and IOC extraction.';
    data.learningObjectives.push('Malware analysis methodologies', 'Static analysis techniques', 'Dynamic analysis and sandboxing', 'Reverse engineering fundamentals', 'IOC extraction');
    data.tools.push('ghidra', 'ida pro', 'x64dbg', 'pestudio', 'remnux', 'cuckoo sandbox', 'any.run', 'procmon');
    data.challenges.push('Analyze malware samples', 'Identify malicious behavior', 'Extract indicators of compromise', 'Reverse engineer malware functionality');
    data.techniques.push('static analysis', 'dynamic analysis', 'reverse engineering', 'behavioral analysis', 'code deobfuscation');
  }

  if (lowerSlug.includes('reverse') || lowerSlug.includes('ghidra') || lowerSlug.includes('ida')) {
    data.description = 'Master reverse engineering with Ghidra and IDA Pro. Learn assembly analysis, decompilation, and binary exploitation.';
    data.learningObjectives.push('Reverse engineering fundamentals', 'Assembly language analysis', 'Decompiler usage', 'Binary patching', 'Anti-reversing techniques');
    data.tools.push('ghidra', 'ida pro', 'radare2', 'binary ninja', 'gdb', 'x64dbg', 'ollydbg');
    data.challenges.push('Reverse engineer binaries', 'Understand program flow', 'Identify vulnerabilities', 'Bypass security mechanisms');
    data.techniques.push('reverse engineering', 'assembly analysis', 'decompilation', 'binary patching', 'anti-debugging bypass');
  }

  if (lowerSlug.includes('buffer') || lowerSlug.includes('overflow')) {
    data.description = 'Learn buffer overflow exploitation. Master stack and heap overflows, shellcode development, and modern exploit mitigation bypass.';
    data.learningObjectives.push('Buffer overflow fundamentals', 'Stack vs heap overflows', 'Shellcode development', 'Exploit mitigation bypass', 'Return-oriented programming');
    data.tools.push('gdb', 'peda', 'pwndbg', 'ghidra', 'pattern_create', 'msfvenom', 'radare2');
    data.challenges.push('Identify buffer overflow vulnerabilities', 'Control execution flow', 'Develop working exploits', 'Bypass ASLR and DEP');
    data.techniques.push('buffer overflow', 'stack smashing', 'heap overflow', 'rop chains', 'shellcode injection', 'aslr bypass', 'dep bypass');
  }

  // Cryptography
  if (categories.includes('Cryptography') || lowerSlug.includes('crypto') || lowerSlug.includes('encryption')) {
    data.description = 'Master cryptographic concepts and cryptanalysis. Learn to identify weak crypto implementations and perform practical attacks.';
    data.learningObjectives.push('Cryptography fundamentals', 'Common crypto weaknesses', 'Hash cracking techniques', 'Encryption attacks', 'PKI vulnerabilities');
    data.tools.push('hashcat', 'john the ripper', 'cyberchef', 'openssl', 'hashid', 'rsatool', 'featherduster');
    data.challenges.push('Identify encryption algorithms', 'Break weak cryptography', 'Crack password hashes', 'Exploit crypto misimplementations');
    data.techniques.push('hash cracking', 'encryption analysis', 'cryptanalysis', 'known plaintext attack', 'padding oracle', 'ecb detection');
  }

  if (lowerSlug.includes('hash') || lowerSlug.includes('crack')) {
    data.description = 'Master password cracking and hash analysis. Learn hash identification, wordlist attacks, rule-based cracking, and GPU acceleration.';
    data.learningObjectives.push('Hash algorithm identification', 'Wordlist-based attacks', 'Rule-based cracking', 'Hybrid attacks', 'GPU acceleration');
    data.tools.push('hashcat', 'john the ripper', 'hashid', 'crackstation', 'ophcrack');
    data.challenges.push('Identify hash types', 'Crack various password hashes', 'Create custom wordlists', 'Optimize cracking performance');
    data.techniques.push('hash cracking', 'wordlist attacks', 'rule-based attacks', 'rainbow tables', 'gpu cracking', 'mask attacks');
  }

  if (lowerSlug.includes('rsa')) {
    data.description = 'Learn RSA cryptography and common implementation flaws. Master attacks against weak RSA implementations.';
    data.learningObjectives.push('RSA algorithm fundamentals', 'Common RSA weaknesses', 'Factorization attacks', 'Small exponent attacks');
    data.tools.push('rsatool', 'python', 'yafu', 'msieve', 'sage');
    data.challenges.push('Factor weak RSA moduli', 'Exploit small public exponents', 'Perform chosen ciphertext attacks');
    data.techniques.push('rsa cryptanalysis', 'factorization', 'wieners attack', 'common modulus attack', 'low exponent attack');
  }

  // Blue Team & SOC
  if (categories.includes('Blue Team') || lowerSlug.includes('soc') || lowerSlug.includes('splunk') || lowerSlug.includes('elk')) {
    data.description = 'Comprehensive security operations and defensive security training. Master log analysis, threat detection, and incident response.';
    data.learningObjectives.push('Security monitoring fundamentals', 'SIEM platform usage', 'Threat hunting techniques', 'Incident response procedures', 'Alert tuning and correlation');
    data.tools.push('splunk', 'elastic stack', 'kibana', 'sigma', 'wireshark', 'suricata', 'zeek', 'osquery');
    data.challenges.push('Analyze security logs', 'Detect malicious activity', 'Investigate security incidents', 'Create detection rules');
    data.techniques.push('log analysis', 'threat hunting', 'incident response', 'siem querying', 'alert correlation', 'ioc identification');
  }

  if (lowerSlug.includes('threat') && lowerSlug.includes('hunt')) {
    data.description = 'Master proactive threat hunting techniques. Learn to identify advanced threats through hypothesis-driven investigation.';
    data.learningObjectives.push('Threat hunting methodologies', 'Hypothesis development', 'Data analysis techniques', 'TTP identification');
    data.tools.push('splunk', 'elk', 'velociraptor', 'osquery', 'sysmon');
    data.challenges.push('Develop hunting hypotheses', 'Analyze system telemetry', 'Identify advanced threats', 'Document findings');
    data.techniques.push('threat hunting', 'hypothesis testing', 'behavioral analysis', 'anomaly detection');
  }

  if (lowerSlug.includes('incident') && lowerSlug.includes('response')) {
    data.description = 'Learn incident response procedures and digital forensics. Master evidence collection, containment strategies, and eradication techniques.';
    data.learningObjectives.push('Incident response lifecycle', 'Evidence preservation', 'Containment strategies', 'Root cause analysis');
    data.tools.push('forensic toolkit', 'volatility', 'autopsy', 'wireshark', 'sysinternals');
    data.challenges.push('Respond to security incidents', 'Collect and preserve evidence', 'Contain threats', 'Perform root cause analysis');
    data.techniques.push('incident response', 'forensic investigation', 'containment', 'eradication', 'recovery');
  }

  // OSINT
  if (categories.includes('OSINT') || lowerSlug.includes('osint')) {
    data.description = 'Master Open Source Intelligence gathering techniques. Learn to collect, analyze, and correlate publicly available information.';
    data.learningObjectives.push('OSINT fundamentals', 'Search engine techniques', 'Social media investigation', 'Domain reconnaissance', 'Operational security');
    data.tools.push('maltego', 'theharvester', 'shodan', 'censys', 'recon-ng', 'spiderfoot', 'google dorks');
    data.challenges.push('Gather OSINT information', 'Correlate data from multiple sources', 'Maintain operational security', 'Document findings');
    data.techniques.push('osint', 'google dorking', 'social media analysis', 'domain reconnaissance', 'people search', 'image analysis');
  }

  if (lowerSlug.includes('shodan')) {
    data.description = 'Master Shodan search engine for internet-connected devices. Learn advanced search queries and vulnerability discovery.';
    data.learningObjectives.push('Shodan search syntax', 'Device fingerprinting', 'Vulnerability discovery', 'API usage');
    data.tools.push('shodan', 'shodan cli', 'censys');
    data.challenges.push('Discover vulnerable devices', 'Create custom search queries', 'Analyze exposure risks');
    data.techniques.push('shodan querying', 'internet scanning', 'device enumeration', 'vulnerability discovery');
  }

  // Web Application Testing
  if (lowerSlug.includes('burp')) {
    data.description = 'Master Burp Suite for web application security testing. Learn proxy interception, automated scanning, and extension development.';
    data.learningObjectives.push('Burp Suite architecture', 'Proxy configuration and usage', 'Intruder attack types', 'Scanner usage', 'Extension development');
    data.tools.push('burp suite professional', 'burp extensions', 'burp collaborator');
    data.challenges.push('Intercept and modify requests', 'Perform automated attacks', 'Develop custom extensions', 'Exploit web vulnerabilities');
    data.techniques.push('proxy interception', 'request manipulation', 'automated scanning', 'fuzzing', 'session handling');
  }

  if (lowerSlug.includes('api')) {
    data.description = 'Learn API security testing methodologies. Master REST and GraphQL API testing, authentication bypass, and authorization flaws.';
    data.learningObjectives.push('API security fundamentals', 'Authentication testing', 'Authorization bypass', 'Rate limiting abuse', 'Mass assignment');
    data.tools.push('postman', 'burp suite', 'curl', 'jwt_tool', 'graphql voyager');
    data.challenges.push('Test API authentication', 'Exploit authorization flaws', 'Abuse rate limiting', 'Exploit mass assignment');
    data.techniques.push('api testing', 'authentication bypass', 'authorization abuse', 'graphql injection', 'jwt attacks');
  }

  if (lowerSlug.includes('jwt') || lowerSlug.includes('token')) {
    data.description = 'Master JSON Web Token (JWT) security testing. Learn JWT structure, common vulnerabilities, and exploitation techniques.';
    data.learningObjectives.push('JWT structure and standards', 'Algorithm confusion attacks', 'Token manipulation', 'Signature bypass');
    data.tools.push('jwt_tool', 'burp suite', 'cyberchef');
    data.challenges.push('Decode and analyze JWTs', 'Exploit algorithm confusion', 'Bypass signature verification');
    data.techniques.push('jwt manipulation', 'algorithm confusion', 'none attack', 'weak secret', 'kid injection');
  }

  // Container & Cloud Security
  if (lowerSlug.includes('docker') || lowerSlug.includes('container')) {
    data.description = 'Master container security and Docker exploitation. Learn container escape techniques, image analysis, and orchestration security.';
    data.learningObjectives.push('Container security fundamentals', 'Docker architecture', 'Container escape techniques', 'Image vulnerability analysis');
    data.tools.push('docker', 'docker-compose', 'trivy', 'clair', 'docker-bench-security');
    data.challenges.push('Exploit container misconfigurations', 'Escape Docker containers', 'Analyze container images', 'Exploit orchestration platforms');
    data.techniques.push('container escape', 'docker exploitation', 'privilege escalation', 'image analysis', 'registry exploitation');
  }

  if (lowerSlug.includes('kubernetes') || lowerSlug.includes('k8s')) {
    data.description = 'Learn Kubernetes security and exploitation. Master pod security, RBAC abuse, and cluster compromise techniques.';
    data.learningObjectives.push('Kubernetes architecture', 'Pod security policies', 'RBAC exploitation', 'API server attacks');
    data.tools.push('kubectl', 'kubeletctl', 'kube-hunter', 'kubesploit');
    data.challenges.push('Enumerate Kubernetes clusters', 'Exploit RBAC misconfigurations', 'Escape pod restrictions', 'Compromise cluster');
    data.techniques.push('kubernetes exploitation', 'rbac abuse', 'pod escape', 'api exploitation', 'service account abuse');
  }

  if (lowerSlug.includes('cloud') || lowerSlug.includes('aws') || lowerSlug.includes('azure')) {
    data.description = 'Master cloud security and penetration testing. Learn cloud-specific vulnerabilities, misconfigurations, and attack techniques.';
    data.learningObjectives.push('Cloud security fundamentals', 'IAM exploitation', 'Storage misconfiguration', 'Serverless security');
    data.tools.push('aws cli', 'azure cli', 'pacu', 'prowler', 'scoutsuite', 'cloudsploit');
    data.challenges.push('Enumerate cloud resources', 'Exploit IAM misconfigurations', 'Access misconfigured storage', 'Compromise cloud infrastructure');
    data.techniques.push('cloud enumeration', 'iam exploitation', 'metadata service abuse', 'privilege escalation', 'lateral movement');
  }

  // CTF & Challenges
  if (lowerSlug.includes('ctf') || lowerSlug.includes('challenge')) {
    data.description = 'CTF-style challenge room covering multiple security domains. Test your skills across various cybersecurity disciplines.';
    data.learningObjectives.push('CTF methodologies', 'Multi-domain problem solving', 'Tool selection and usage', 'Time management in CTFs');
    data.tools.push('various ctf tools', 'python', 'bash', 'burp suite', 'ghidra');
    data.challenges.push('Solve diverse security challenges', 'Find hidden flags', 'Chain multiple vulnerabilities', 'Think creatively');
    data.techniques.push('ctf techniques', 'flag hunting', 'multi-stage exploitation', 'lateral thinking');
  }

  if (lowerSlug.includes('steganography') || lowerSlug.includes('stego')) {
    data.description = 'Learn steganography and hidden data detection. Master techniques to hide and extract data from various file formats.';
    data.learningObjectives.push('Steganography fundamentals', 'Image analysis', 'Audio steganography', 'Text-based hiding');
    data.tools.push('steghide', 'stegsolve', 'binwalk', 'exiftool', 'zsteg', 'sonic visualizer');
    data.challenges.push('Extract hidden data from images', 'Analyze audio files', 'Detect steganographic content');
    data.techniques.push('steganography', 'lsb analysis', 'metadata extraction', 'file carving', 'spectral analysis');
  }

  // Default for unrecognized patterns
  if (data.learningObjectives.length === 0) {
    data.description = `Explore ${title} and develop practical cybersecurity skills. This hands-on room provides real-world scenarios and challenges.`;
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
