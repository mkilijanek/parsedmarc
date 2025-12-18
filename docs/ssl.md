# SSL/TLS Documentation

## Overview

The application uses Nginx as a TLS-terminating reverse proxy with automatic certificate management.

---

## SSL Setup

### Automated (Recommended)

```bash
./scripts/setup-ssl.sh
```

Creates:
- Self-signed certificate for development
- 2048-bit RSA key
- 365-day validity
- Stored in `./ssl/`

### Manual

```bash
# Generate private key
openssl genrsa -out ssl/key.pem 2048

# Generate certificate
openssl req -new -x509 -key ssl/key.pem -out ssl/cert.pem -days 365
```

---

## Production Certificates

### Let's Encrypt

```bash
# Install certbot
apt-get install certbot python3-certbot-nginx

# Obtain certificate
certbot certonly --nginx -d your-domain.com

# Configure paths
SSL_CERT_PATH=/etc/letsencrypt/live/your-domain.com/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/your-domain.com/privkey.pem
```

### Commercial CA

1. Generate CSR
2. Submit to CA
3. Receive certificate
4. Configure paths in `.env`

---

## Configuration

### Environment Variables

```bash
SSL_CERT_PATH=./ssl/cert.pem
SSL_KEY_PATH=./ssl/key.pem
SSL_CHAIN_PATH=./ssl/chain.pem  # Optional
```

### Nginx Config

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:...';
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

---

## Security Features

- **TLS 1.2+** only
- **Modern cipher suites**
- **HSTS** header
- **OCSP stapling** (if chain provided)
- **HTTP/2** enabled

---

## Troubleshooting

### Certificate Errors

```bash
# Verify certificate
openssl x509 -in ssl/cert.pem -text -noout

# Check expiration
openssl x509 -in ssl/cert.pem -noout -enddate

# Test TLS handshake
openssl s_client -connect localhost:7003
```

### Browser Warnings

Self-signed certificates trigger warnings:
- Click "Advanced" → "Proceed"
- Or import certificate to trusted store

---

## See Also

- [Configuration](configuration.md) - SSL variables
- [DEPLOYMENT.md](../DEPLOYMENT.md) - Production setup
