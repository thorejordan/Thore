# API-Dokumentation

Vollständige Dokumentation der TryHackMe Dashboard REST API.

## Base URL

```
http://localhost:5000/api
```

## Authentifizierung

Aktuell ist keine Authentifizierung erforderlich. In zukünftigen Versionen wird JWT-basierte Authentifizierung implementiert.

## Endpoints

### 1. Rooms

#### GET `/rooms`

Liefert eine paginierte Liste von TryHackMe-Räumen mit Filteroptionen.

**Query Parameters:**

| Parameter | Typ | Default | Beschreibung |
|-----------|-----|---------|--------------|
| `page` | number | 1 | Seitennummer |
| `limit` | number | 20 | Anzahl Ergebnisse pro Seite |
| `search` | string | - | Volltext-Suchbegriff |
| `difficulty` | string | - | Filter nach Schwierigkeitsgrad |
| `tags` | string | - | Komma-getrennte Liste von Tags |
| `sortBy` | string | name | Sortierfeld |
| `sortOrder` | string | asc | Sortierrichtung (asc/desc) |

**Beispiel-Request:**
```bash
GET /api/rooms?difficulty=Easy&tags=web,linux&page=1&limit=20
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "name": "blue",
      "slug": "blue",
      "title": "Blue",
      "difficulty": "Easy",
      "categories": ["Windows", "Blue Team"],
      "tags": ["windows", "eternal-blue", "forensics"],
      "description": "Deploy & hack into a Windows machine, leveraging common misconfigurations issues.",
      "learningObjectives": [
        "Understanding EternalBlue vulnerability",
        "Windows exploitation basics"
      ],
      "tools": ["nmap", "metasploit"],
      "techniques": ["port scanning", "exploitation"],
      "challenges": ["Find and exploit EternalBlue"],
      "writeupSources": [],
      "metadata": {
        "estimatedTime": "1 hour",
        "points": 100
      },
      "lastUpdated": "2024-01-15T10:30:00.000Z",
      "createdAt": "2024-01-01T10:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 1000,
    "pages": 50
  }
}
```

---

#### GET `/rooms/:slug`

Liefert Details zu einem spezifischen TryHackMe-Raum.

**URL Parameters:**

| Parameter | Typ | Beschreibung |
|-----------|-----|--------------|
| `slug` | string | Eindeutiger Raum-Identifier |

**Beispiel-Request:**
```bash
GET /api/rooms/blue
```

**Response:**
```json
{
  "success": true,
  "data": {
    "_id": "507f1f77bcf86cd799439011",
    "name": "blue",
    "slug": "blue",
    "title": "Blue",
    "difficulty": "Easy",
    "categories": ["Windows", "Blue Team"],
    "tags": ["windows", "eternal-blue", "forensics"],
    "description": "Deploy & hack into a Windows machine...",
    "learningObjectives": ["..."],
    "tools": ["nmap", "metasploit"],
    "techniques": ["port scanning", "exploitation"],
    "challenges": ["Find and exploit EternalBlue"],
    "writeupSources": [
      {
        "url": "https://github.com/user/writeup",
        "platform": "GitHub",
        "author": "username",
        "scrapedAt": "2024-01-15T10:30:00.000Z"
      }
    ],
    "scrapedData": {
      "summary": "This room covers the EternalBlue exploit...",
      "keySteps": [
        "1. Scan for SMB vulnerabilities",
        "2. Exploit using Metasploit"
      ],
      "commonPitfalls": ["Don't forget to set LHOST"]
    },
    "metadata": {
      "estimatedTime": "1 hour",
      "points": 100,
      "popularity": 95
    },
    "lastUpdated": "2024-01-15T10:30:00.000Z",
    "createdAt": "2024-01-01T10:00:00.000Z"
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "message": "Room not found"
}
```

---

#### GET `/rooms/stats`

Liefert aggregierte Statistiken über alle Räume.

**Response:**
```json
{
  "success": true,
  "data": {
    "total": 1000,
    "byDifficulty": [
      { "_id": "Easy", "count": 350 },
      { "_id": "Medium", "count": 400 },
      { "_id": "Hard", "count": 200 },
      { "_id": "Insane", "count": 30 },
      { "_id": "Unknown", "count": 20 }
    ],
    "topTags": [
      { "_id": "web", "count": 250 },
      { "_id": "linux", "count": 200 },
      { "_id": "windows", "count": 180 }
    ],
    "topTools": [
      { "_id": "nmap", "count": 450 },
      { "_id": "burp suite", "count": 200 },
      { "_id": "metasploit", "count": 180 }
    ]
  }
}
```

---

#### GET `/rooms/tags`

Liefert eine Liste aller verfügbaren Tags.

**Response:**
```json
{
  "success": true,
  "data": [
    "advent-of-cyber",
    "blue-team",
    "challenge",
    "containers",
    "cryptography",
    "ctf",
    "forensics",
    "linux",
    "malware",
    "networking",
    "offensive",
    "osint",
    "red-team",
    "reverse-engineering",
    "tools",
    "vulnerability",
    "web",
    "windows"
  ]
}
```

---

#### GET `/rooms/categories`

Liefert eine Liste aller Kategorien.

**Response:**
```json
{
  "success": true,
  "data": [
    "Blue Team",
    "Cloud Security",
    "Container Security",
    "Cryptography",
    "Forensics",
    "General",
    "Linux",
    "Malware Analysis",
    "Network Security",
    "OSINT",
    "Purple Team",
    "Red Team",
    "Web Security",
    "Windows"
  ]
}
```

---

### 2. Health Check

#### GET `/health`

Prüft den Status der API.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

---

## Error Responses

Alle Endpoints können folgende Fehler zurückgeben:

### 400 Bad Request
```json
{
  "success": false,
  "message": "Invalid request parameters"
}
```

### 404 Not Found
```json
{
  "success": false,
  "message": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "success": false,
  "message": "Internal server error",
  "error": "Error details (nur im Development Mode)"
}
```

---

## Filtering & Searching

### Difficulty Filter

Gültige Werte:
- `Easy`
- `Medium`
- `Hard`
- `Insane`
- `Unknown`

**Beispiel:**
```bash
GET /api/rooms?difficulty=Easy
```

### Tag Filter

Mehrere Tags können mit Kommas getrennt werden:

**Beispiel:**
```bash
GET /api/rooms?tags=web,linux,ctf
```

### Full-Text Search

Durchsucht Name, Titel, Beschreibung und Tags:

**Beispiel:**
```bash
GET /api/rooms?search=windows+privilege+escalation
```

### Kombinierte Filter

**Beispiel:**
```bash
GET /api/rooms?difficulty=Medium&tags=web&search=sql&sortBy=title&sortOrder=desc
```

---

## Pagination

Alle Listen-Endpoints unterstützen Pagination:

```bash
GET /api/rooms?page=2&limit=50
```

**Response enthält:**
```json
{
  "pagination": {
    "page": 2,
    "limit": 50,
    "total": 1000,
    "pages": 20
  }
}
```

---

## Sorting

Verfügbare Sortierfelder:
- `name`
- `title`
- `difficulty`
- `createdAt`
- `lastUpdated`

**Beispiel:**
```bash
GET /api/rooms?sortBy=lastUpdated&sortOrder=desc
```

---

## Rate Limiting

Aktuell keine Rate Limits implementiert.

**Geplant:**
- 100 Requests pro Minute pro IP
- 1000 Requests pro Stunde pro IP

---

## CORS

CORS ist aktiviert für alle Origins im Development Mode.

Im Production Mode sollte nur die Frontend-Domain erlaubt werden.

---

## WebSocket (Geplant)

Zukünftige Version wird WebSocket-Support für Echtzeit-Updates bieten:

```javascript
ws://localhost:5000/ws
```

Events:
- `room:updated` - Raum wurde aktualisiert
- `room:created` - Neuer Raum erstellt
- `stats:updated` - Statistiken aktualisiert

---

## Beispiel-Integration

### JavaScript/TypeScript

```typescript
import axios from 'axios';

const API_BASE = 'http://localhost:5000/api';

// Räume abrufen
const getRooms = async (filters) => {
  const params = new URLSearchParams(filters);
  const response = await axios.get(`${API_BASE}/rooms?${params}`);
  return response.data;
};

// Einzelnen Raum abrufen
const getRoom = async (slug) => {
  const response = await axios.get(`${API_BASE}/rooms/${slug}`);
  return response.data;
};

// Statistiken abrufen
const getStats = async () => {
  const response = await axios.get(`${API_BASE}/rooms/stats`);
  return response.data;
};
```

### Python

```python
import requests

API_BASE = 'http://localhost:5000/api'

# Räume abrufen
def get_rooms(filters=None):
    response = requests.get(f'{API_BASE}/rooms', params=filters)
    return response.json()

# Einzelnen Raum abrufen
def get_room(slug):
    response = requests.get(f'{API_BASE}/rooms/{slug}')
    return response.json()

# Statistiken abrufen
def get_stats():
    response = requests.get(f'{API_BASE}/rooms/stats')
    return response.json()
```

### cURL

```bash
# Räume mit Filtern abrufen
curl "http://localhost:5000/api/rooms?difficulty=Easy&limit=10"

# Einzelnen Raum abrufen
curl "http://localhost:5000/api/rooms/blue"

# Statistiken abrufen
curl "http://localhost:5000/api/rooms/stats"

# Tags abrufen
curl "http://localhost:5000/api/rooms/tags"
```
