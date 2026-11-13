# Deployment & Operation Guide (DEPLOYMENT_GUIDE.md) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Prerequisites & System Requirements

- **Operating System:** Linux (Ubuntu 22.04+ / Debian 12+), macOS (13+), or Windows (10/11 / Server 2022).
- **Python Runtime:** Python 3.11 or newer (Python 3.14 compatible).
- **Node.js Runtime:** Node.js 18.x or 20.x LTS, with npm 9.x+.
- **Disk Space:** Minimum 500 MB for application, dependencies, and evidence storage.
- **Memory (RAM):** Minimum 2 GB (4 GB recommended for concurrent triage).

---

### 2. Local Standalone Setup & Execution

#### Step 1: Environment Configuration
Clone or navigate to the project directory:
```powershell
cd D:\Projects\04-PhishGuard-Email-URL-Analyzer
```

Create the `.env` file from `.env.example`:
```powershell
Copy-Item .env.example .env
```

Verify or adjust environment variables in `.env`:
```ini
ENVIRONMENT=development
LOG_LEVEL=INFO
HOST=127.0.0.1
PORT=8000
DATABASE_URL=sqlite:///./data/phishguard.db
EVIDENCE_DIR=./data/evidence
REPORTS_DIR=./data/reports
RATE_LIMIT_PER_MINUTE=60
MAX_UPLOAD_SIZE_BYTES=10485760
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

#### Step 2: Backend Setup
Create and activate a virtual environment:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install backend dependencies:
```powershell
pip install -r backend/requirements.txt
```

Run database migrations:
```powershell
cd backend
python -m alembic upgrade head
cd ..
```

Start the FastAPI backend engine:
```powershell
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
*The database seeder automatically initializes the 27 deterministic detection rules on startup.*

#### Step 3: Frontend Setup
In a separate terminal window:
```powershell
cd D:\Projects\04-PhishGuard-Email-URL-Analyzer\frontend
npm install
npm run dev
```
Open your browser and navigate to `http://localhost:5173`. The live engine badge in the top right will display **Engine Status: HEALTHY**.

---

### 3. Containerized Deployment (Docker & Compose)

For production or isolated SOC lab deployments, PhishGuard can be deployed via Docker with egress network isolation.

#### Dockerfile (Backend)
```dockerfile
FROM python:3.12-slim AS backend
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libxml2-dev libxslt-dev && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY .env.example .env
RUN mkdir -p data/evidence data/reports
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose Configuration (`docker-compose.yml`)
```yaml
version: '3.8'

services:
  phishguard-backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - phishguard-data:/app/data
    environment:
      - ENVIRONMENT=production
      - HOST=0.0.0.0
      - PORT=8000
      - DATABASE_URL=sqlite:////app/data/phishguard.db
    # Enforce air-gap: disable external internet egress
    networks:
      internal-net:

  phishguard-frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "127.0.0.1:5173:80"
    depends_on:
      - phishguard-backend
    networks:
      internal-net:

networks:
  internal-net:
    internal: true # Disables external WAN routing

volumes:
  phishguard-data:
```

---

### 4. Production Hardening Checklist

1. **Strict Loopback Binding:** Never bind the backend to `0.0.0.0` unless deployed in an isolated internal Docker network with firewall egress blocking.
2. **Reverse Proxy TLS:** Place the web console behind Nginx or Caddy with TLS 1.3, HSTS headers, and strict reverse proxy timeouts.
3. **Evidence Vault Access Controls:** Restrict read and write permissions on `data/evidence/` to the application runtime service user (`chmod 700 data/evidence`).
4. **Firewall Egress Filtering:** In SOC production environments, apply an outbound iptables rule blocking all egress traffic from the PhishGuard application host to guarantee zero possibility of adversary canary beaconing.

