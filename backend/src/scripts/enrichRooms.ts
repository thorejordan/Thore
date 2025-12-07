import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Room from '../models/Room';

dotenv.config();

interface EnrichmentData {
  learningObjectives: string[];
  tools: string[];
  challenges: string[];
  techniques: string[];
  description?: string;
}

// Intelligent pattern-based enrichment
function enrichRoomData(slug: string, title: string, categories: string[]): EnrichmentData {
  const data: EnrichmentData = {
    learningObjectives: [],
    tools: [],
    challenges: [],
    techniques: [],
  };

  const lowerSlug = slug.toLowerCase();
  const lowerTitle = title.toLowerCase();

  // Web Security rooms
  if (lowerSlug.includes('sql') || lowerSlug.includes('sqli')) {
    data.learningObjectives.push('Understanding SQL injection vulnerabilities', 'Database exploitation techniques');
    data.tools.push('sqlmap', 'burp suite', 'browser devtools');
    data.challenges.push('Identify SQL injection points', 'Extract database information', 'Bypass authentication');
    data.techniques.push('sql injection', 'database enumeration', 'error-based injection');
    data.description = 'Learn about SQL injection vulnerabilities and how to exploit them';
  }

  if (lowerSlug.includes('xss') || lowerSlug.includes('cross-site')) {
    data.learningObjectives.push('Understanding XSS vulnerabilities', 'Client-side security');
    data.tools.push('burp suite', 'browser', 'xss hunter');
    data.challenges.push('Find XSS vulnerabilities', 'Craft malicious payloads', 'Bypass filters');
    data.techniques.push('xss', 'dom manipulation', 'cookie stealing');
  }

  if (lowerSlug.includes('owasp')) {
    data.learningObjectives.push('Understanding OWASP Top 10 vulnerabilities', 'Web application security fundamentals');
    data.tools.push('burp suite', 'zap', 'browser devtools', 'nikto');
    data.challenges.push('Exploit multiple OWASP vulnerabilities', 'Understand common web flaws');
    data.techniques.push('injection', 'broken authentication', 'sensitive data exposure', 'xxe');
  }

  if (lowerSlug.includes('lfi') || lowerSlug.includes('file-inclusion')) {
    data.learningObjectives.push('Understanding Local File Inclusion', 'File traversal attacks');
    data.tools.push('burp suite', 'curl', 'browser');
    data.challenges.push('Exploit LFI to read sensitive files', 'Achieve remote code execution');
    data.techniques.push('lfi', 'path traversal', 'log poisoning');
  }

  if (lowerSlug.includes('ssrf')) {
    data.learningObjectives.push('Understanding Server-Side Request Forgery', 'Internal network exploitation');
    data.tools.push('burp suite', 'curl');
    data.challenges.push('Exploit SSRF vulnerabilities', 'Access internal resources');
    data.techniques.push('ssrf', 'port scanning', 'cloud metadata exploitation');
  }

  // Network/Recon
  if (lowerSlug.includes('nmap') || lowerSlug.includes('scan')) {
    data.learningObjectives.push('Network scanning fundamentals', 'Service enumeration');
    data.tools.push('nmap', 'masscan', 'rustscan');
    data.challenges.push('Scan target network', 'Identify running services', 'Find vulnerabilities');
    data.techniques.push('port scanning', 'service enumeration', 'os detection');
  }

  if (lowerSlug.includes('enum') || lowerSlug.includes('recon')) {
    data.learningObjectives.push('Enumeration techniques', 'Information gathering');
    data.tools.push('nmap', 'gobuster', 'enum4linux', 'ldapsearch');
    data.challenges.push('Enumerate target system', 'Gather useful information');
    data.techniques.push('enumeration', 'reconnaissance', 'osint');
  }

  // Windows
  if (categories.includes('Windows') || lowerSlug.includes('windows')) {
    data.learningObjectives.push('Windows exploitation techniques', 'Active Directory security');
    data.tools.push('nmap', 'metasploit', 'powershell', 'mimikatz');
    data.challenges.push('Exploit Windows vulnerabilities', 'Escalate privileges');
    data.techniques.push('windows exploitation', 'privilege escalation');
  }

  if (lowerSlug.includes('active-directory') || lowerSlug.includes('ad-')) {
    data.learningObjectives.push('Active Directory enumeration', 'AD attack techniques');
    data.tools.push('bloodhound', 'powerview', 'rubeus', 'mimikatz', 'impacket');
    data.challenges.push('Enumerate AD environment', 'Exploit AD misconfigurations', 'Achieve domain admin');
    data.techniques.push('kerberoasting', 'asreproasting', 'pass-the-hash', 'golden ticket');
  }

  if (lowerSlug.includes('powershell')) {
    data.learningObjectives.push('PowerShell for pentesting', 'Windows scripting');
    data.tools.push('powershell', 'powerview', 'empire');
    data.challenges.push('Use PowerShell for enumeration', 'Exploit using PowerShell');
    data.techniques.push('powershell', 'scripting', 'windows exploitation');
  }

  // Linux
  if (categories.includes('Linux') || lowerSlug.includes('linux')) {
    data.learningObjectives.push('Linux privilege escalation', 'Linux exploitation');
    data.tools.push('linpeas', 'linenum', 'pspy', 'gtfobins');
    data.challenges.push('Gain initial access', 'Escalate to root privileges');
    data.techniques.push('privilege escalation', 'suid exploitation', 'sudo abuse');
  }

  if (lowerSlug.includes('privesc') || lowerSlug.includes('privilege')) {
    data.learningObjectives.push('Privilege escalation techniques', 'Post-exploitation');
    data.tools.push('linpeas', 'winpeas', 'pspy', 'gtfobins');
    data.challenges.push('Find privilege escalation vectors', 'Escalate to root/administrator');
    data.techniques.push('privilege escalation', 'suid/sgid', 'sudo', 'kernel exploits');
  }

  // Metasploit
  if (lowerSlug.includes('metasploit') || lowerSlug.includes('msfvenom')) {
    data.learningObjectives.push('Metasploit framework usage', 'Exploit development');
    data.tools.push('metasploit', 'msfvenom', 'meterpreter');
    data.challenges.push('Use Metasploit to exploit targets', 'Create custom payloads');
    data.techniques.push('exploitation', 'payload generation', 'post-exploitation');
  }

  // Forensics
  if (categories.includes('Forensics') || lowerSlug.includes('forensic')) {
    data.learningObjectives.push('Digital forensics fundamentals', 'Evidence analysis');
    data.tools.push('autopsy', 'volatility', 'wireshark', 'strings', 'exiftool');
    data.challenges.push('Analyze forensic artifacts', 'Recover deleted data', 'Timeline analysis');
    data.techniques.push('disk forensics', 'memory analysis', 'network forensics');
  }

  if (lowerSlug.includes('memory') || lowerSlug.includes('volatility')) {
    data.learningObjectives.push('Memory forensics', 'RAM analysis');
    data.tools.push('volatility', 'rekall');
    data.challenges.push('Analyze memory dump', 'Extract credentials', 'Identify processes');
    data.techniques.push('memory analysis', 'process injection detection');
  }

  if (lowerSlug.includes('wireshark') || lowerSlug.includes('packet') || lowerSlug.includes('pcap')) {
    data.learningObjectives.push('Network traffic analysis', 'Protocol analysis');
    data.tools.push('wireshark', 'tshark', 'tcpdump');
    data.challenges.push('Analyze network traffic', 'Identify suspicious activity', 'Extract data');
    data.techniques.push('packet analysis', 'protocol inspection', 'traffic filtering');
  }

  // Malware
  if (categories.includes('Malware Analysis') || lowerSlug.includes('malware')) {
    data.learningObjectives.push('Malware analysis techniques', 'Reverse engineering');
    data.tools.push('ghidra', 'ida', 'x64dbg', 'pestudio', 'remnux');
    data.challenges.push('Analyze malware sample', 'Identify malicious behavior', 'Extract IOCs');
    data.techniques.push('static analysis', 'dynamic analysis', 'reverse engineering');
  }

  if (lowerSlug.includes('reverse') || lowerSlug.includes('ghidra') || lowerSlug.includes('ida')) {
    data.learningObjectives.push('Reverse engineering fundamentals', 'Binary analysis');
    data.tools.push('ghidra', 'ida', 'radare2', 'gdb');
    data.challenges.push('Reverse engineer binary', 'Find vulnerabilities', 'Understand program flow');
    data.techniques.push('reverse engineering', 'assembly analysis', 'debugging');
  }

  // Cryptography
  if (categories.includes('Cryptography') || lowerSlug.includes('crypto') || lowerSlug.includes('encryption')) {
    data.learningObjectives.push('Cryptography fundamentals', 'Breaking weak crypto');
    data.tools.push('hashcat', 'john', 'cyberchef', 'openssl');
    data.challenges.push('Break weak encryption', 'Crack passwords', 'Understand crypto algorithms');
    data.techniques.push('hash cracking', 'encryption analysis', 'cryptanalysis');
  }

  if (lowerSlug.includes('hash') || lowerSlug.includes('crack')) {
    data.learningObjectives.push('Password cracking', 'Hash analysis');
    data.tools.push('hashcat', 'john', 'crackstation');
    data.challenges.push('Identify hash types', 'Crack password hashes');
    data.techniques.push('hash cracking', 'wordlist attacks', 'rainbow tables');
  }

  // Blue Team
  if (categories.includes('Blue Team') || lowerSlug.includes('soc') || lowerSlug.includes('splunk') || lowerSlug.includes('elk')) {
    data.learningObjectives.push('Security monitoring', 'Threat detection');
    data.tools.push('splunk', 'elastic', 'sigma', 'wireshark');
    data.challenges.push('Detect malicious activity', 'Analyze logs', 'Respond to incidents');
    data.techniques.push('log analysis', 'threat hunting', 'incident response');
  }

  // OSINT
  if (categories.includes('OSINT') || lowerSlug.includes('osint')) {
    data.learningObjectives.push('Open Source Intelligence gathering', 'Information discovery');
    data.tools.push('google', 'shodan', 'maltego', 'theHarvester');
    data.challenges.push('Gather OSINT information', 'Find hidden data', 'Track digital footprint');
    data.techniques.push('osint', 'google dorking', 'social engineering');
  }

  // Burp Suite
  if (lowerSlug.includes('burp')) {
    data.learningObjectives.push('Burp Suite mastery', 'Web application testing');
    data.tools.push('burp suite', 'burp extensions');
    data.challenges.push('Use Burp Suite features', 'Intercept and modify requests');
    data.techniques.push('proxy interception', 'request manipulation', 'automated scanning');
  }

  // CTF challenges
  if (lowerSlug.includes('ctf') || lowerSlug.includes('challenge')) {
    data.learningObjectives.push('CTF problem solving', 'Multiple attack vectors');
    data.tools.push('various ctf tools');
    data.challenges.push('Solve CTF challenges', 'Find hidden flags');
    data.techniques.push('ctf techniques', 'creative problem solving');
  }

  // Docker/Container
  if (lowerSlug.includes('docker') || lowerSlug.includes('container')) {
    data.learningObjectives.push('Container security', 'Docker exploitation');
    data.tools.push('docker', 'docker-compose', 'kubectl');
    data.challenges.push('Exploit container misconfigurations', 'Escape containers');
    data.techniques.push('container escape', 'docker exploitation');
  }

  // Remove duplicates
  data.learningObjectives = [...new Set(data.learningObjectives)];
  data.tools = [...new Set(data.tools)];
  data.challenges = [...new Set(data.challenges)];
  data.techniques = [...new Set(data.techniques)];

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
    let skipped = 0;

    for (const room of rooms) {
      const enrichmentData = enrichRoomData(room.slug, room.title, room.categories);

      // Only update if we have meaningful data
      if (enrichmentData.learningObjectives.length > 0 || enrichmentData.tools.length > 0) {
        await Room.updateOne(
          { _id: room._id },
          {
            $set: {
              learningObjectives: enrichmentData.learningObjectives,
              tools: enrichmentData.tools,
              challenges: enrichmentData.challenges,
              techniques: enrichmentData.techniques,
              description: enrichmentData.description || room.description,
              lastUpdated: new Date(),
            },
          }
        );
        enriched++;

        if (enriched % 50 === 0) {
          console.log(`📊 Progress: ${enriched}/${rooms.length} rooms enriched`);
        }
      } else {
        skipped++;
      }
    }

    console.log('\n✅ Enrichment complete!');
    console.log(`📊 Statistics:`);
    console.log(`   - Enriched: ${enriched}`);
    console.log(`   - Skipped: ${skipped}`);
    console.log(`   - Total: ${rooms.length}`);

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
