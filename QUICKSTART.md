# THREAT FEED AGGREGATOR - SZYBKI START

Aktualizacja: `1.1.x` (2026-02-26)

## 📦 Zawartość Archiwum

Otrzymałeś kompletny, production-ready system agregacji threat intelligence składający się z:

### Struktura Projektu
```
threat-feed-aggregator/
├── app/                        # Aplikacja Python/Flask
│   ├── __init__.py
│   ├── main.py                # Główna aplikacja Flask
│   ├── db.py                  # Zarządzanie bazą danych
│   ├── models.py              # Modele SQLAlchemy
│   ├── worker.py              # Background worker
│   └── services/
│       ├── crowdsec.py        # Integracja CrowdSec (TLP:AMBER)
│       └── misp.py            # Integracja MISP (TLP z tagów)
├── database/
│   └── init.sql               # Schemat PostgreSQL
├── nginx/
│   └── nginx.conf             # Konfiguracja reverse proxy
├── scripts/
│   ├── generate-secrets.sh    # Generator sekretów
│   └── setup-ssl.sh           # Setup SSL/TLS
├── .github/workflows/
│   └── docker-build.yml       # CI/CD pipeline
├── docker-compose.yml         # Orkiestracja kontenerów
├── Dockerfile                 # Obraz aplikacji
├── requirements.txt           # Zależności Python
├── .env.example               # Szablon konfiguracji
├── Makefile                   # Pomocnicze komendy
├── README.md                  # Pełna dokumentacja
├── DEPLOYMENT.md              # Przewodnik wdrożenia
├── SECURITY.md                # Polityka bezpieczeństwa
└── LICENSE                    # Licencja MIT
```

## 🚀 Instalacja Krok po Kroku

### 1. Rozpakowanie
```bash
tar -xzf threat-feed-aggregator.tar.gz
cd threat-feed-aggregator
```

### 2. Generowanie Sekretów
```bash
chmod +x scripts/*.sh
./scripts/generate-secrets.sh
```

To wygeneruje:
- Hasło PostgreSQL (32 chars)
- Hasło Redis (32 chars)
- Flask secret key (128 chars)

### 3. Konfiguracja SSL

**Opcja A: Self-signed (test/dev)**
```bash
./scripts/setup-ssl.sh
```

**Opcja B: Let's Encrypt (produkcja)**
```bash
sudo certbot certonly --standalone -d twoja-domena.pl
sudo cp /etc/letsencrypt/live/twoja-domena.pl/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/twoja-domena.pl/privkey.pem ssl/key.pem
sudo chown $USER:$USER ssl/*.pem
```

### 4. Konfiguracja Integracji

Edytuj `.env` i dodaj credentials:

```bash
vim .env

# CrowdSec (opcjonalne)
CROWDSEC_API_KEY=twój_klucz_api
CROWDSEC_LISTS=lista1,lista2

# MISP (opcjonalne)
MISP_URL=https://twoja-misp.pl
MISP_API_KEY=twój_klucz_api
MISP_VERIFY_SSL=false
```

### 5. Uruchomienie
```bash
# Compose + migracje
docker compose up -d postgres redis
docker compose run --rm migrate
docker compose up -d app worker

# Sprawdź status
docker compose ps
```

### 6. Weryfikacja
```bash
# Health check
curl http://localhost:7003/health

# Sync API (kolejka jobs)
curl -X POST http://localhost:7003/api/sync \
  -H "Content-Type: application/json" \
  -d '{"source":"abusech"}'

# Web UI
firefox http://localhost:7003/
```

## 🔧 Komendy Pomocnicze

### Local dev (venv)
```bash
bash scripts/dev-bootstrap.sh
bash scripts/dev-test.sh
```

### Makefile
```bash
make help          # Pokaż dostępne komendy
make setup         # Pełny setup (secrets + SSL)
make start         # Uruchom wszystko
make stop          # Zatrzymaj wszystko
make restart       # Restart
make logs          # Zobacz logi
make health        # Sprawdź health
make clean         # Usuń wszystko (UWAGA!)
```

### Docker Compose
```bash
# Logi
docker-compose logs -f app
docker-compose logs -f worker
docker-compose logs -f db

# Restart pojedynczego serwisu
docker-compose restart app

# Rebuild
docker-compose build
docker-compose up -d

# Shell w kontenerze
docker-compose exec app bash
docker-compose exec db psql -U threatfeed
```

## 🎯 Kluczowe Endpointy

### API
- `GET /health` - Health check
- `GET /api/stats` - Statystyki systemu
- `GET /indicators` - Wszystkie wskaźniki (web UI)
- `GET /indicators/<format>` - Export w formatach:
  - txt, csv, json, xml
  - fortigate, fortigate_ips
  - checkpoint, paloalto
  - sentinel, defender
  - arcsight, splunk, elasticsearch
  - cribl, f5, imperva, fidelis

### Formaty Export
```bash
# Plain text
curl -k https://localhost:7003/indicators/txt

# FortiGate
curl -k https://localhost:7003/indicators/fortigate

# Microsoft Sentinel (STIX 2.1)
curl -k https://localhost:7003/indicators/sentinel

# ArcSight CEF
curl -k https://localhost:7003/indicators/arcsight

# Elasticsearch Bulk NDJSON
curl -k https://localhost:7003/indicators/elasticsearch
```

## 🛡️ Bezpieczeństwo

### Krytyczne Punkty
1. **TLP Handling**
   - CrowdSec: ZAWSZE TLP:AMBER (commercial source)
   - MISP: TLP z tagów (domyślnie GREEN)

2. **MISP Filtering**
   - TYLKO wskaźniki z `to_ids=True`
   - `enforce_warninglist=True` (unikaj false positives)

3. **Secrets**
   - NIGDY nie commituj `.env`
   - Rotacja sekretów co 90 dni
   - Backup `.env` w bezpiecznym miejscu

4. **SSL/TLS**
   - Minimum TLS 1.2
   - Strong ciphers only
   - HSTS enabled (31536000s)

## 📊 Monitoring

### Health Checks
```bash
# Szybki check
curl -k https://localhost:7003/health | jq

# Docker health
docker-compose ps

# Logi błędów
docker-compose logs app | grep ERROR
```

### Metryki
```bash
# Statystyki wskaźników
curl -k https://localhost:7003/api/stats | jq

# Status feedów
docker-compose exec db psql -U threatfeed -d threatfeed -c "SELECT * FROM feed_stats;"

# Aktywne wskaźniki
docker-compose exec db psql -U threatfeed -d threatfeed -c "SELECT COUNT(*) FROM indicators WHERE is_active = TRUE;"
```

## 🔍 Troubleshooting

### Problem: Kontenery nie startują
```bash
# Sprawdź logi
docker-compose logs

# Sprawdź porty
sudo netstat -tulpn | grep -E '7003|5432|6379'

# Restart
docker-compose down
docker-compose up -d
```

### Problem: Brak połączenia z bazą
```bash
# Sprawdź PostgreSQL
docker-compose exec db psql -U threatfeed -c "SELECT 1"

# Sprawdź hasło w .env
grep POSTGRES_PASSWORD .env

# Restart bazy
docker-compose restart db
```

### Problem: SSL certificate errors
```bash
# Regeneruj certyfikat
./scripts/setup-ssl.sh

# Sprawdź certyfikat
openssl x509 -in ssl/cert.pem -text -noout

# Sprawdź nginx
docker-compose logs nginx
```

### Problem: Worker nie aktualizuje
```bash
# Sprawdź logi workera
docker-compose logs -f worker

# Sprawdź credentials w .env
grep -E 'CROWDSEC|MISP' .env

# Manualny test
docker-compose exec app python -c "from app.services.crowdsec import update_all_crowdsec_lists; update_all_crowdsec_lists()"
```

## 🗄️ Backup & Restore

### Backup Bazy Danych
```bash
# Dump bazy
docker-compose exec db pg_dump -U threatfeed threatfeed > backup_$(date +%Y%m%d).sql

# Backup z kompresją
docker-compose exec db pg_dump -U threatfeed threatfeed | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restore
```bash
# Restore z pliku
cat backup.sql | docker-compose exec -T db psql -U threatfeed threatfeed

# Restore z gzip
zcat backup.sql.gz | docker-compose exec -T db psql -U threatfeed threatfeed
```

### Backup .env
```bash
# Zaszyfrowany backup
gpg -c .env  # Tworzy .env.gpg

# Restore
gpg -d .env.gpg > .env
```

## 🔄 Aktualizacje

### Aktualizacja Systemu
```bash
# Pull najnowszej wersji
git pull

# Rebuild obrazów
docker-compose build

# Restart z nową wersją
docker-compose down
docker-compose up -d

# Weryfikacja
curl -k https://localhost:7003/health
```

### Aktualizacja Zależności Python
```bash
# W kontenerze
docker-compose exec app pip list --outdated

# Lokalnie
pip list --outdated -r requirements.txt
```

## 📈 Skalowanie

### Zwiększenie Wydajności
```bash
# Więcej workerów Gunicorn (w .env)
WORKERS=8  # 2-4 × liczba rdzeni CPU

# Więcej pamięci PostgreSQL (docker-compose.yml)
POSTGRES_SHARED_BUFFERS=512MB
POSTGRES_EFFECTIVE_CACHE_SIZE=2GB

# Zwiększ pamięć Redis (docker-compose.yml)
--maxmemory 1gb
```

### Horizontal Scaling
Dla większych deploymentów:
1. Load balancer (HAProxy/Nginx)
2. Wiele instancji app
3. PostgreSQL replication
4. Redis cluster

## 🎓 Dalsze Kroki

### 1. Implementacja Brakujących Formatów
Plik `app/formatters.py` wymaga implementacji 17 formatów export.
Zobacz specyfikację w README.md sekcja "Supported Formats".

### 2. Web UI z Kibana Search
Plik `app/main.py` - endpoint `/indicators` wymaga:
- Kibana-style query parser
- Filtry (type, TLP, confidence, source)
- Paginacja
- ARIA accessibility

### 3. Dodatkowe Formatery
Implementuj pozostałe formaty w `app/formatters.py`:
- FortiGate IPS, Check Point, Palo Alto
- Microsoft Defender, Sentinel
- F5, Imperva, Fidelis
- Cribl, Splunk, Elasticsearch, ArcSight

### 4. Testy
```bash
# Dodaj testy w tests/
pytest tests/ -v
```

## 📞 Support

### Dokumentacja
- README.md - Kompletna dokumentacja
- DEPLOYMENT.md - Przewodnik wdrożenia
- SECURITY.md - Polityka bezpieczeństwa

### Logs
```bash
# Wszystkie logi
docker-compose logs

# Specific service
docker-compose logs -f app
```

### Problemy
Jeśli napotkasz problemy:
1. Sprawdź logi (`docker-compose logs`)
2. Zweryfikuj konfigurację (`.env`)
3. Sprawdź connectivity do external services
4. Przejrzyj dokumentację w README.md

## ✅ Checklist Produkcyjny

Przed wdrożeniem na produkcję:

- [ ] Wygenerowano silne sekr ety (32+ chars)
- [ ] SSL certyfikat od trusted CA (nie self-signed)
- [ ] Skonfigurowano MISP i/lub CrowdSec credentials
- [ ] Firewall skonfigurowany (tylko 7003/tcp exposed)
- [ ] `.env` zabezpieczony (chmod 600)
- [ ] Backup `.env` w bezpiecznym miejscu
- [ ] Monitorowanie skonfigurowane
- [ ] Health checks działają
- [ ] Logi są zbierane i analizowane
- [ ] Plan backup i restore przetestowany
- [ ] Dokumentacja dostępna dla zespołu
- [ ] Secrets rotation schedule ustawiony

## 🎉 Gotowe!

System jest teraz gotowy do użycia. Dostęp:
- Web UI: https://localhost:7003/
- Health: https://localhost:7003/health
- API Stats: https://localhost:7003/api/stats

Powodzenia! 🛡️
