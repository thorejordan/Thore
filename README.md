# TryHackMe Dashboard

Eine vollständige, responsive Web-Applikation für die interaktive Exploration und Analyse von TryHackMe-Räumen mit automatisierter Datenakquise und intelligenter Filterung.

## 🌟 Features

### Frontend-Funktionalitäten
- **Interaktives Dashboard**: Grid-basiertes Layout mit responsive Design für alle Bildschirmgrößen
- **Room Cards**: Übersichtliche Darstellung von Metadaten (Schwierigkeitsgrad, Kategorien, Tags, Tools)
- **Modal-Detailansicht**: Umfassende Informationen zu jedem TryHackMe-Raum
- **Erweiterte Filterung**:
  - Volltextsuche über alle Rauminformationen
  - Filter nach Schwierigkeitsgrad (Easy, Medium, Hard, Insane)
  - Tag-basierte Filterung
  - Kombinierbare Filteroptionen
- **Pagination**: Effiziente Navigation durch große Datenmengen
- **Responsive Design**: Optimiert für Desktop, Tablet und Mobile

### Backend-Funktionalitäten
- **REST API**: Vollständige CRUD-Operationen für TryHackMe-Räume
- **Web Scraping**: Automatisierte Datenakquise von externen Quellen
  - GitHub-Integration zur Suche nach Writeups
  - Medium-Unterstützung (erweiterbar)
  - Generische Web-Scraping-Engine
- **Intelligente Kategorisierung**: Automatische Zuweisung von Kategorien und Tags
- **MongoDB-Integration**: Performante Datenpersistenz mit Indexierung
- **Statistische Auswertungen**: Aggregierte Daten über Schwierigkeitsgrade, Tags und Tools

## 🏗️ Architektur

```
tryhackme-dashboard/
├── frontend/               # React + TypeScript + TailwindCSS
│   ├── src/
│   │   ├── components/    # React-Komponenten
│   │   │   ├── Dashboard.tsx
│   │   │   ├── RoomCard.tsx
│   │   │   ├── RoomModal.tsx
│   │   │   ├── FilterBar.tsx
│   │   │   └── Pagination.tsx
│   │   ├── hooks/         # Custom React Hooks
│   │   ├── services/      # API-Integration
│   │   ├── types/         # TypeScript-Definitionen
│   │   └── utils/         # Hilfsfunktionen
│   └── package.json
│
├── backend/               # Node.js + Express + TypeScript
│   ├── src/
│   │   ├── models/        # MongoDB-Modelle
│   │   ├── routes/        # API-Routen
│   │   ├── controllers/   # Request-Handler
│   │   ├── services/      # Business-Logik
│   │   │   └── scraperService.ts
│   │   ├── config/        # Konfiguration
│   │   ├── data/          # Statische Daten
│   │   └── scripts/       # Utility-Skripte
│   └── package.json
│
└── README.md
```

## 🚀 Installation & Setup

### Voraussetzungen
- Node.js (v18+)
- MongoDB (v6+)
- npm oder yarn

### 1. Repository klonen
```bash
git clone <repository-url>
cd Thore
```

### 2. Dependencies installieren
```bash
npm run install:all
```

### 3. Umgebungsvariablen konfigurieren

**Backend (.env)**
```bash
cd backend
cp .env.example .env
```

Editieren Sie `backend/.env`:
```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/tryhackme-dashboard
NODE_ENV=development
```

**Frontend (.env)**
```bash
cd frontend
cp .env.example .env
```

### 4. MongoDB starten
```bash
# Auf Linux/Mac
mongod --dbpath /path/to/data

# Auf Windows
mongod.exe --dbpath C:\path\to\data

# Oder mit Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### 5. Datenbank initialisieren
```bash
cd backend
npm run build
node dist/scripts/initializeRooms.js
```

Dies verarbeitet alle 1000 TryHackMe-Räume und speichert sie in der Datenbank.

### 6. Applikation starten

**Option A: Beide Services gleichzeitig (Entwicklung)**
```bash
npm run dev
```

**Option B: Separat starten**

Backend:
```bash
cd backend
npm run dev
```

Frontend (in neuem Terminal):
```bash
cd frontend
npm run dev
```

### 7. Applikation öffnen
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000/api

## 📊 Datenmodell

### Room Schema
```typescript
{
  name: string;              // Eindeutiger Raumname
  slug: string;              // URL-freundlicher Slug
  title: string;             // Anzeigename
  difficulty: string;        // Easy | Medium | Hard | Insane | Unknown
  categories: string[];      // Kategorien (Web Security, Linux, etc.)
  tags: string[];           // Suchbare Tags
  description?: string;      // Raumbeschreibung
  learningObjectives: string[]; // Lernziele
  tools: string[];          // Empfohlene Tools
  challenges: string[];      // Hauptaufgaben
  techniques: string[];      // Verwendete Techniken
  writeupSources: [{        // Externe Writeup-Quellen
    url: string;
    platform: string;
    author?: string;
  }];
  scrapedData?: {           // Gescrapte Zusatzinformationen
    summary?: string;
    keySteps?: string[];
    commonPitfalls?: string[];
  };
}
```

## 🔌 API-Dokumentation

### Endpoints

#### GET `/api/rooms`
Liefert paginierte Liste aller Räume mit Filteroptionen.

**Query-Parameter:**
- `page` (number): Seitennummer (default: 1)
- `limit` (number): Ergebnisse pro Seite (default: 20)
- `search` (string): Volltextsuche
- `difficulty` (string): Filter nach Schwierigkeitsgrad
- `tags` (string): Komma-getrennte Tag-Liste
- `sortBy` (string): Sortierfeld (default: 'name')
- `sortOrder` ('asc' | 'desc'): Sortierrichtung

**Beispiel:**
```bash
GET /api/rooms?difficulty=Easy&tags=web,linux&page=1&limit=20
```

#### GET `/api/rooms/:slug`
Liefert Details zu einem spezifischen Raum.

**Beispiel:**
```bash
GET /api/rooms/blue
```

#### GET `/api/rooms/stats`
Liefert aggregierte Statistiken.

**Response:**
```json
{
  "total": 1000,
  "byDifficulty": [...],
  "topTags": [...],
  "topTools": [...]
}
```

#### GET `/api/rooms/tags`
Liefert alle verfügbaren Tags.

#### GET `/api/rooms/categories`
Liefert alle Kategorien.

## 🛠️ Technologie-Stack

### Frontend
- **React 18**: UI-Framework
- **TypeScript**: Type-safe Development
- **Vite**: Build-Tool & Dev-Server
- **TailwindCSS**: Utility-first CSS Framework
- **Lucide React**: Icon-Bibliothek
- **Axios**: HTTP-Client

### Backend
- **Node.js**: Runtime-Umgebung
- **Express**: Web-Framework
- **TypeScript**: Type-safe Development
- **MongoDB + Mongoose**: NoSQL-Datenbank
- **Puppeteer**: Headless Browser für Web Scraping
- **Cheerio**: HTML-Parser
- **Axios**: HTTP-Client

## 🔍 Web Scraping

Das Backend enthält ein modulares Web-Scraping-System:

### Scraper-Service Features
- **GitHub-Integration**: Suche nach Writeups via GitHub API
- **Medium-Support**: Vorbereitet für Medium-Scraping (erfordert Anti-Bot-Maßnahmen)
- **Generischer Scraper**: Statische und dynamische Seiten
- **Content-Extraktion**: Automatische Erkennung von Tools, Techniken und Schritten

### Scraping ausführen
```bash
cd backend
npm run scrape
```

## 📱 Responsive Design

Das Dashboard ist vollständig responsive:
- **Desktop (1024px+)**: 3-Spalten Grid
- **Tablet (768px-1023px)**: 2-Spalten Grid
- **Mobile (<768px)**: 1-Spalte

## 🎨 UI/UX Features

### Room Cards
- Kompakte Übersicht mit wichtigsten Metadaten
- Farbcodierung nach Schwierigkeitsgrad
- Hover-Effekte für bessere Interaktivität
- Statistik-Badges (Tags, Tools, Lernziele)

### Modal-Detailansicht
- Vollständige Rauminformationen
- Organisierte Sections für verschiedene Datentypen
- Links zu externen Ressourcen
- Direkter Link zum TryHackMe-Raum

### Filter-System
- Echtzeit-Suche
- Multi-Select Tag-Filter
- Schwierigkeitsgrad-Filter
- Clear-All-Funktion
- Aktive Filter werden angezeigt

## 🚧 Erweiterungsmöglichkeiten

### Geplante Features
1. **Erweiterte Scraping-Integration**
   - Medium API-Integration
   - Reddit-Scraping
   - Blog-Aggregation

2. **Benutzerverwaltung**
   - User Accounts
   - Progress Tracking
   - Favoriten/Bookmarks

3. **Analytik**
   - Lernfortschritt-Dashboard
   - Empfehlungssystem
   - Schwierigkeitstrends

4. **Social Features**
   - Writeup-Sharing
   - Kommentare
   - Bewertungen

## 🐛 Troubleshooting

### MongoDB Connection Error
```bash
# Prüfen Sie, ob MongoDB läuft
mongosh

# Bei Docker
docker ps | grep mongo
```

### Port bereits belegt
```bash
# Backend (Port 5000)
lsof -ti:5000 | xargs kill -9

# Frontend (Port 3000)
lsof -ti:3000 | xargs kill -9
```

### Build-Fehler
```bash
# Dependencies neu installieren
rm -rf node_modules package-lock.json
rm -rf frontend/node_modules frontend/package-lock.json
rm -rf backend/node_modules backend/package-lock.json
npm run install:all
```

## 📄 Lizenz

MIT License

## 👥 Autor

Entwickelt für die TryHackMe Community

## 🙏 Danksagungen

- TryHackMe für die großartige Plattform
- Community Writeup-Autoren
- Open Source Contributors
