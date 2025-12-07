# Quick Start Guide

Schnellanleitung zum Starten der TryHackMe Dashboard-Applikation in 5 Minuten.

## Voraussetzungen

- Node.js v18+ installiert
- MongoDB installiert und laufend

## Setup in 5 Schritten

### 1. Dependencies installieren (2 Min)

```bash
npm run install:all
```

### 2. Environment-Variablen kopieren (30 Sek)

```bash
# Backend
cp backend/.env.example backend/.env

# Frontend
cp frontend/.env.example frontend/.env
```

### 3. MongoDB starten (30 Sek)

**Docker (empfohlen):**
```bash
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

**Lokal:**
```bash
mongod --dbpath /path/to/data
```

### 4. Datenbank initialisieren (1 Min)

```bash
cd backend
npm run build
node dist/scripts/initializeRooms.js
cd ..
```

### 5. Applikation starten (30 Sek)

```bash
npm run dev
```

## Fertig!

Die Applikation ist nun verfügbar unter:

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000/api

## Erste Schritte

1. **Räume durchsuchen**: Öffnen Sie http://localhost:3000
2. **Filter verwenden**: Klicken Sie auf "Filters" und wählen Sie Schwierigkeitsgrad oder Tags
3. **Details anzeigen**: Klicken Sie auf eine Room Card für detaillierte Informationen
4. **API testen**: Öffnen Sie http://localhost:5000/api/rooms/stats

## Troubleshooting

**MongoDB Connection Error?**
```bash
# Prüfen ob MongoDB läuft
docker ps | grep mongo
# oder
mongosh
```

**Port belegt?**
```bash
# Port 5000 (Backend)
lsof -ti:5000 | xargs kill -9

# Port 3000 (Frontend)
lsof -ti:3000 | xargs kill -9
```

**Datenbank leer?**
```bash
cd backend
node dist/scripts/initializeRooms.js
```

## Nächste Schritte

- Lesen Sie die vollständige [README.md](README.md)
- Entdecken Sie die [API-Dokumentation](API.md)
- Lernen Sie über [Deployment](DEPLOYMENT.md)

## Entwicklung

**Backend neu starten:**
```bash
cd backend
npm run dev
```

**Frontend neu starten:**
```bash
cd frontend
npm run dev
```

**Beide neu builden:**
```bash
npm run build
```

## Demo-Daten

Die Applikation wird mit 1000 TryHackMe-Räumen initialisiert, die automatisch kategorisiert werden:

- ✅ Easy: ~350 Räume
- ⚠️ Medium: ~400 Räume
- 🔥 Hard: ~200 Räume
- 💀 Insane: ~30 Räume
- ❓ Unknown: ~20 Räume

## Support

Bei Problemen:
1. Prüfen Sie die Logs in der Konsole
2. Lesen Sie die [Troubleshooting-Sektion](README.md#troubleshooting)
3. Öffnen Sie ein GitHub Issue
