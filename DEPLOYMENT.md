# Deployment-Anleitung

Diese Anleitung beschreibt die Bereitstellung der TryHackMe Dashboard-Applikation in verschiedenen Umgebungen.

## 📦 Production Build

### Backend
```bash
cd backend
npm run build
```

Dies erstellt den kompilierten Code im `dist/` Verzeichnis.

### Frontend
```bash
cd frontend
npm run build
```

Dies erstellt eine optimierte Production-Build im `dist/` Verzeichnis.

## 🐳 Docker Deployment

### Dockerfile für Backend

`backend/Dockerfile`:
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 5000

CMD ["node", "dist/index.js"]
```

### Dockerfile für Frontend

`frontend/Dockerfile`:
```dockerfile
FROM node:18-alpine as build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### Docker Compose

`docker-compose.yml`:
```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:latest
    container_name: tryhackme-mongodb
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    environment:
      - MONGO_INITDB_DATABASE=tryhackme-dashboard

  backend:
    build: ./backend
    container_name: tryhackme-backend
    ports:
      - "5000:5000"
    environment:
      - PORT=5000
      - MONGODB_URI=mongodb://mongodb:27017/tryhackme-dashboard
      - NODE_ENV=production
    depends_on:
      - mongodb
    restart: unless-stopped

  frontend:
    build: ./frontend
    container_name: tryhackme-frontend
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: unless-stopped

volumes:
  mongodb_data:
```

### Starten mit Docker Compose
```bash
docker-compose up -d
```

## ☁️ Cloud Deployment

### Vercel (Frontend)

1. Frontend nach GitHub pushen
2. Vercel-Account erstellen
3. Projekt importieren
4. Build-Konfiguration:
   - Framework Preset: Vite
   - Build Command: `npm run build`
   - Output Directory: `dist`
5. Umgebungsvariable setzen:
   - `VITE_API_URL`: URL Ihres Backend-APIs

### Heroku (Backend)

```bash
# Heroku CLI installieren
heroku login
heroku create tryhackme-dashboard-api

# MongoDB Add-on
heroku addons:create mongolab:sandbox

# Environment Variables
heroku config:set NODE_ENV=production

# Deploy
git subtree push --prefix backend heroku main
```

### DigitalOcean / AWS / Azure

1. **VPS/EC2 einrichten**
2. **MongoDB installieren**
3. **Node.js installieren**
4. **PM2 für Process Management**:

```bash
# PM2 installieren
npm install -g pm2

# Backend starten
cd backend
pm2 start dist/index.js --name tryhackme-api

# Frontend mit nginx
cd frontend
npm run build
# Build nach /var/www/html kopieren
```

5. **Nginx als Reverse Proxy**:

`/etc/nginx/sites-available/tryhackme`:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Frontend
    location / {
        root /var/www/html;
        try_files $uri /index.html;
    }

    # Backend API Proxy
    location /api {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 🔒 Sicherheits-Checkliste

- [ ] Umgebungsvariablen für sensible Daten verwenden
- [ ] CORS richtig konfigurieren
- [ ] Rate Limiting implementieren
- [ ] HTTPS aktivieren
- [ ] MongoDB-Authentifizierung aktivieren
- [ ] Regelmäßige Backups einrichten
- [ ] Security Headers setzen
- [ ] Input Validation
- [ ] Dependency Updates

## 🔐 SSL/HTTPS mit Let's Encrypt

```bash
# Certbot installieren
sudo apt-get install certbot python3-certbot-nginx

# Zertifikat erstellen
sudo certbot --nginx -d your-domain.com

# Auto-Renewal testen
sudo certbot renew --dry-run
```

## 📊 Monitoring

### PM2 Monitoring
```bash
pm2 monit
pm2 logs
pm2 restart all
```

### Logs
```bash
# Backend logs
tail -f backend/logs/app.log

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

## 🔄 CI/CD Pipeline

### GitHub Actions

`.github/workflows/deploy.yml`:
```yaml
name: Deploy

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'

    - name: Install dependencies
      run: npm run install:all

    - name: Build
      run: npm run build

    - name: Deploy to server
      uses: appleboy/ssh-action@master
      with:
        host: ${{ secrets.HOST }}
        username: ${{ secrets.USERNAME }}
        key: ${{ secrets.SSH_KEY }}
        script: |
          cd /path/to/app
          git pull
          npm run install:all
          npm run build
          pm2 restart all
```

## 🎯 Performance-Optimierung

1. **Caching**
   - Redis für API-Caching
   - CDN für statische Assets
   - Browser-Caching Headers

2. **Database**
   - Indexes für häufige Queries
   - Connection Pooling
   - Query-Optimierung

3. **Frontend**
   - Code Splitting
   - Lazy Loading
   - Image Optimization
   - Gzip Compression

## 📈 Skalierung

### Horizontal Scaling
- Load Balancer (nginx/HAProxy)
- Mehrere Backend-Instanzen
- MongoDB Replica Set
- Redis für Session Management

### Vertical Scaling
- Server-Ressourcen erhöhen
- Database Performance Tuning
- Caching-Strategien
