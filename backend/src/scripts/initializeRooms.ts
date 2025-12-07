import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Room from '../models/Room';
import { TRYHACKME_ROOMS } from '../data/rooms';
import scraperService from '../services/scraperService';

dotenv.config();

// Helper function to generate title from slug
function slugToTitle(slug: string): string {
  return slug
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// Helper function to categorize rooms based on their names
function categorizeRoom(slug: string): {
  difficulty: string;
  categories: string[];
  tags: string[];
} {
  const lowerSlug = slug.toLowerCase();

  let difficulty = 'Unknown';
  const categories: string[] = [];
  const tags: string[] = [];

  // Difficulty inference
  if (lowerSlug.includes('easy') || lowerSlug.includes('basic') || lowerSlug.includes('intro')) {
    difficulty = 'Easy';
  } else if (lowerSlug.includes('hard') || lowerSlug.includes('advanced')) {
    difficulty = 'Hard';
  } else if (lowerSlug.includes('medium') || lowerSlug.includes('intermediate')) {
    difficulty = 'Medium';
  }

  // Category detection
  if (lowerSlug.includes('web') || lowerSlug.includes('owasp') || lowerSlug.includes('xss') ||
      lowerSlug.includes('sql') || lowerSlug.includes('ssrf') || lowerSlug.includes('ssti')) {
    categories.push('Web Security');
    tags.push('web');
  }

  if (lowerSlug.includes('windows') || lowerSlug.includes('active-directory') || lowerSlug.includes('ad-')) {
    categories.push('Windows');
    tags.push('windows');
  }

  if (lowerSlug.includes('linux') || lowerSlug.includes('privilege-escalation') || lowerSlug.includes('privesc')) {
    categories.push('Linux');
    tags.push('linux');
  }

  if (lowerSlug.includes('forensics') || lowerSlug.includes('memory') || lowerSlug.includes('volatility')) {
    categories.push('Forensics');
    tags.push('forensics');
  }

  if (lowerSlug.includes('malware') || lowerSlug.includes('reverse') || lowerSlug.includes('ghidra')) {
    categories.push('Malware Analysis');
    tags.push('malware', 'reverse-engineering');
  }

  if (lowerSlug.includes('network') || lowerSlug.includes('wireshark') || lowerSlug.includes('packet')) {
    categories.push('Network Security');
    tags.push('networking');
  }

  if (lowerSlug.includes('crypto') || lowerSlug.includes('encryption')) {
    categories.push('Cryptography');
    tags.push('cryptography');
  }

  if (lowerSlug.includes('osint') || lowerSlug.includes('recon')) {
    categories.push('OSINT');
    tags.push('osint', 'reconnaissance');
  }

  if (lowerSlug.includes('blue') || lowerSlug.includes('soc') || lowerSlug.includes('splunk') ||
      lowerSlug.includes('elk') || lowerSlug.includes('defensive')) {
    categories.push('Blue Team');
    tags.push('blue-team', 'defensive');
  }

  if (lowerSlug.includes('red') || lowerSlug.includes('pentest') || lowerSlug.includes('offensive')) {
    categories.push('Red Team');
    tags.push('red-team', 'offensive');
  }

  if (lowerSlug.includes('purple')) {
    categories.push('Purple Team');
    tags.push('purple-team');
  }

  if (lowerSlug.includes('cloud') || lowerSlug.includes('azure') || lowerSlug.includes('aws')) {
    categories.push('Cloud Security');
    tags.push('cloud');
  }

  if (lowerSlug.includes('docker') || lowerSlug.includes('kubernetes') || lowerSlug.includes('container')) {
    categories.push('Container Security');
    tags.push('containers');
  }

  if (lowerSlug.includes('burp') || lowerSlug.includes('nmap') || lowerSlug.includes('metasploit')) {
    tags.push('tools');
  }

  if (lowerSlug.includes('cve-')) {
    tags.push('vulnerability', 'cve');
  }

  if (lowerSlug.includes('ctf')) {
    tags.push('ctf');
  }

  if (lowerSlug.includes('advent')) {
    tags.push('advent-of-cyber', 'challenge');
  }

  // Default category if none found
  if (categories.length === 0) {
    categories.push('General');
  }

  return { difficulty, categories, tags };
}

async function initializeRooms() {
  try {
    console.log('🔄 Connecting to database...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tryhackme-dashboard');
    console.log('✅ Connected to database');

    console.log(`🔄 Processing ${TRYHACKME_ROOMS.length} rooms...`);

    let created = 0;
    let updated = 0;
    let errors = 0;

    for (const slug of TRYHACKME_ROOMS) {
      try {
        const existingRoom = await Room.findOne({ slug });

        const { difficulty, categories, tags } = categorizeRoom(slug);
        const title = slugToTitle(slug);

        const roomData = {
          name: slug,
          slug: slug,
          title: title,
          difficulty: difficulty as any,
          categories,
          tags,
          learningObjectives: [],
          tools: [],
          challenges: [],
          techniques: [],
          writeupSources: [],
          lastUpdated: new Date()
        };

        if (existingRoom) {
          await Room.updateOne({ slug }, { $set: roomData });
          updated++;
        } else {
          await Room.create(roomData);
          created++;
        }

        if ((created + updated) % 50 === 0) {
          console.log(`📊 Progress: ${created + updated}/${TRYHACKME_ROOMS.length} rooms processed`);
        }
      } catch (error) {
        errors++;
        console.error(`❌ Error processing room ${slug}:`, error);
      }
    }

    console.log('\n✅ Initialization complete!');
    console.log(`📊 Statistics:`);
    console.log(`   - Created: ${created}`);
    console.log(`   - Updated: ${updated}`);
    console.log(`   - Errors: ${errors}`);
    console.log(`   - Total: ${TRYHACKME_ROOMS.length}`);

    await mongoose.disconnect();
    console.log('👋 Disconnected from database');
  } catch (error) {
    console.error('❌ Fatal error:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  initializeRooms();
}

export default initializeRooms;
