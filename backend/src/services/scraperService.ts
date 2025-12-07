import axios from 'axios';
import * as cheerio from 'cheerio';
import puppeteer, { Browser, Page } from 'puppeteer';

export interface ScrapedData {
  title?: string;
  content: string;
  author?: string;
  platform: string;
  url: string;
}

export class ScraperService {
  private browser: Browser | null = null;

  async initBrowser(): Promise<void> {
    if (!this.browser) {
      this.browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
    }
  }

  async closeBrowser(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  /**
   * Search for writeups on Medium
   */
  async searchMedium(roomName: string): Promise<ScrapedData[]> {
    const searchQuery = `${roomName} tryhackme writeup`;
    const results: ScrapedData[] = [];

    try {
      // Medium search is often blocked by anti-scraping measures
      // This is a simplified version
      const searchUrl = `https://medium.com/search?q=${encodeURIComponent(searchQuery)}`;

      // Note: In production, you might need to use Puppeteer or a paid API
      console.log(`Searching Medium: ${searchUrl}`);

      // Placeholder - real implementation would require handling Medium's anti-scraping
      return results;
    } catch (error) {
      console.error(`Error scraping Medium for ${roomName}:`, error);
      return results;
    }
  }

  /**
   * Search for writeups on GitHub
   */
  async searchGitHub(roomName: string): Promise<ScrapedData[]> {
    const results: ScrapedData[] = [];
    const searchQuery = `${roomName} tryhackme`;

    try {
      // GitHub search API (rate limited without auth)
      const response = await axios.get(
        `https://api.github.com/search/repositories?q=${encodeURIComponent(searchQuery)}&sort=stars&order=desc`,
        {
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'TryHackMe-Dashboard'
          }
        }
      );

      const repos = response.data.items.slice(0, 3); // Top 3 results

      for (const repo of repos) {
        results.push({
          title: repo.name,
          content: repo.description || '',
          author: repo.owner.login,
          platform: 'GitHub',
          url: repo.html_url
        });
      }

      return results;
    } catch (error) {
      console.error(`Error searching GitHub for ${roomName}:`, error);
      return results;
    }
  }

  /**
   * Generic web scraper using Cheerio (for static content)
   */
  async scrapeStaticPage(url: string): Promise<string> {
    try {
      const response = await axios.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        timeout: 10000
      });

      const $ = cheerio.load(response.data);

      // Remove script and style elements
      $('script, style, nav, footer, header').remove();

      // Extract main content
      const content = $('article, main, .content, .post-content').text() || $('body').text();

      return content.trim().replace(/\s+/g, ' ').substring(0, 5000);
    } catch (error) {
      console.error(`Error scraping ${url}:`, error);
      return '';
    }
  }

  /**
   * Dynamic page scraper using Puppeteer
   */
  async scrapeDynamicPage(url: string): Promise<string> {
    await this.initBrowser();

    if (!this.browser) {
      throw new Error('Browser not initialized');
    }

    const page: Page = await this.browser.newPage();

    try {
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

      // Extract text content
      const content = await page.evaluate(() => {
        const article = document.querySelector('article, main, .content');
        return article ? article.textContent : document.body.textContent;
      });

      return content?.trim().replace(/\s+/g, ' ').substring(0, 5000) || '';
    } catch (error) {
      console.error(`Error scraping dynamic page ${url}:`, error);
      return '';
    } finally {
      await page.close();
    }
  }

  /**
   * Extract key information from scraped content
   */
  extractKeyInformation(content: string): {
    tools: string[];
    techniques: string[];
    steps: string[];
  } {
    const tools: string[] = [];
    const techniques: string[] = [];
    const steps: string[] = [];

    // Common tools patterns
    const toolPatterns = [
      'nmap', 'gobuster', 'burp suite', 'metasploit', 'sqlmap', 'hydra',
      'john', 'hashcat', 'wireshark', 'nikto', 'dirb', 'ffuf', 'linpeas',
      'winpeas', 'enum4linux', 'smbclient', 'crackmapexec', 'bloodhound'
    ];

    // Common techniques
    const techniquePatterns = [
      'sql injection', 'xss', 'lfi', 'rfi', 'privilege escalation',
      'reverse shell', 'port scanning', 'directory enumeration',
      'password cracking', 'buffer overflow', 'suid', 'sudo'
    ];

    const lowerContent = content.toLowerCase();

    // Extract tools
    toolPatterns.forEach(tool => {
      if (lowerContent.includes(tool)) {
        tools.push(tool);
      }
    });

    // Extract techniques
    techniquePatterns.forEach(technique => {
      if (lowerContent.includes(technique)) {
        techniques.push(technique);
      }
    });

    // Extract numbered steps (simplified)
    const stepMatches = content.match(/\d+\.\s+[A-Z][^\n]{20,100}/g);
    if (stepMatches) {
      steps.push(...stepMatches.slice(0, 5));
    }

    return {
      tools: [...new Set(tools)],
      techniques: [...new Set(techniques)],
      steps
    };
  }
}

export default new ScraperService();
