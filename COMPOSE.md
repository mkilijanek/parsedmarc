# Docker Compose: parsedmarc + msgraph-token-refresh

## Pliki
- `docker-compose.yml` - stack z usługami `parsedmarc` i `msgraph-token-refresh`
- `.env.example` - wymagane zmienne środowiskowe dla odświeżania tokenu
- `ini/parsedmarc.ini.example` - przykładowy plik konfiguracyjny parsedmarc

## Jak uruchomić
1. Skopiuj `.env.example` do `.env` i uzupełnij `TENANT_ID` oraz `CLIENT_ID`.
   Opcjonalnie ustaw `PARSEDMARC_IMAGE` na konkretny tag/digest obrazu.
2. Utwórz plik `secrets/msgraph_client_secret.txt` z tajnym kluczem aplikacji Entra ID.
3. Skopiuj `ini/parsedmarc.ini.example` do `ini/parsedmarc.ini` i uzupełnij konfigurację parsedmarc.
4. Jeśli Twoja konfiguracja parsedmarc korzysta z pliku tokenu, ustaw ścieżkę na `/tokens/.token.json`.
5. Uruchom: `docker compose up -d --build`.
6. Sprawdź kondycję usług: `docker compose ps` oraz `docker compose logs -f parsedmarc msgraph-token-refresh`.

## Uwagi
- Token jest odświeżany przez `msgraph-token-refresh` i zapisywany w współdzielonym wolumenie `msgraph_tokens`.
- Serwis `parsedmarc` montuje ten wolumen w trybie tylko do odczytu.
- `parsedmarc` startuje dopiero po utworzeniu pierwszego pliku tokenu (`healthcheck` na `msgraph-token-refresh`).
- Obie usługi mają `restart: unless-stopped` (łagodzenie problemów przejściowych MS Graph).
- Dla dużych skrzynek stosuj wzorzec backfill + steady-state opisany w `OPERATIONS.md`.
