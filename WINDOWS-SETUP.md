# TryHackMe Dashboard - Windows Setup Guide

## PowerShell-spezifische Befehle

### 1. Dependencies installieren
```powershell
npm run install:all
```

### 2. Environment-Variablen einrichten
```powershell
# Backend
Copy-Item backend\.env.example backend\.env

# Frontend
Copy-Item frontend\.env.example frontend\.env
```

### 3. MongoDB starten (Docker)
```powershell
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

**ODER** MongoDB lokal:
```powershell
mongod --dbpath C:\data\db
```

### 4. Backend builden und Datenbank initialisieren
```powershell
cd backend
npm run build
node dist/scripts/initializeRooms.js
cd ..
```

**ODER** mit ts-node (ohne Build):
```powershell
cd backend
npm run init-db
cd ..
```

### 5. Applikation starten

**Option A: Beide Services (2 Terminals benötigt)**

Terminal 1 - Backend:
```powershell
cd backend
npm run dev
```

Terminal 2 - Frontend:
```powershell
cd frontend
npm run dev
```

**Option B: Root-Verzeichnis (wenn concurrently funktioniert)**
```powershell
npm run dev
```

## Troubleshooting

### TypeScript Build Error

Wenn der Frontend-Build fehlschlägt:

```powershell
cd frontend
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install
npm run build
```

### Nodemon nicht gefunden

```powershell
cd backend
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install
```

Verwenden Sie stattdessen:
```powershell
npm run dev
```
(Das verwendet ts-node statt nodemon)

### MongoDB Verbindungsfehler

Prüfen Sie ob MongoDB läuft:
```powershell
# Docker
docker ps

# Lokal - öffnen Sie ein neues PowerShell-Fenster
mongosh
```

### Port bereits belegt

```powershell
# Port 5000 freigeben (Backend)
Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess | Stop-Process -Force

# Port 3000 freigeben (Frontend)
Get-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess | Stop-Process -Force
```

## Schnellstart für Windows

```powershell
# 1. Dependencies installieren
npm run install:all

# 2. .env Dateien erstellen
Copy-Item backend\.env.example backend\.env
Copy-Item frontend\.env.example frontend\.env

# 3. MongoDB starten (Docker)
docker run -d -p 27017:27017 --name mongodb mongo:latest

# 4. Datenbank initialisieren
cd backend
npm run init-db
cd ..

# 5. Backend starten (Terminal 1)
cd backend
npm run dev

# In neuem Terminal: Frontend starten (Terminal 2)
cd frontend
npm run dev
```

## Alternativen ohne &&-Operator

PowerShell verwendet `;` statt `&&`:

```powershell
# Bash (Linux/Mac)
cd backend && npm run build && node dist/scripts/initializeRooms.js

# PowerShell (Windows)
cd backend; npm run build; node dist/scripts/initializeRooms.js
```

ODER Schritt für Schritt:
```powershell
cd backend
npm run build
node dist/scripts/initializeRooms.js
```

## URLs

Nach dem Start:
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000/api
- API Stats: http://localhost:5000/api/rooms/stats
