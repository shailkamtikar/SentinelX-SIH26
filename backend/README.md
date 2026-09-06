# SentinelX Backend — Step 1: Real .eml Ingestion

Parses real RFC-822/MIME `.eml` files into structured JSON using only
Python's standard-library `email` package. No mocked data, no AI/ML,
no threat intelligence — that's later stages.

## Run locally

Requires [uv](https://docs.astral.sh/uv/).

```bash
cd backend
uv sync
uv run uvicorn app.main:app --reload --port 8000
```

The server assumes it is started from the `backend/` directory (so
`app.main:app` resolves). It listens on `http://localhost:8000`.

If you don't use uv, `requirements.txt` is kept in sync via
`uv export --no-hashes --no-dev -o requirements.txt` for a plain
`pip install -r requirements.txt` + `uvicorn app.main:app` workflow.

## Endpoints

### `GET /health`

Returns `{"status": "ok", "service": "sentinelx-backend"}` — confirms the
process is running.

### `POST /analyze-email`

- **Content type:** `multipart/form-data`
- **Field name:** `file`
- **Accepted files:** `.eml` only (rejected otherwise with `400`)

Uploaded bytes are parsed with `email.parser.BytesParser` under
`email.policy.default`, which decodes RFC 2047 encoded headers
automatically. Response schema:

```json
{
  "sender": "string | null",
  "recipient": "string | null",
  "subject": "string | null",
  "reply_to": "string | null",
  "date": "string | null",
  "message_id": "string | null",
  "return_path": "string | null",
  "body": "string | null",
  "attachments": [
    { "filename": "string | null", "content_type": "string", "size": 0 }
  ],
  "urls": ["string"]
}
```

- `body` prefers the `text/plain` part; falls back to `text/html` with
  tags stripped (via `html.parser.HTMLParser`, never rendered/executed).
- `urls` combines URLs found in the plain-text body and `<a href>`
  values from the HTML part, de-duplicated.
- A header that isn't present in the email is `null` — nothing is
  invented to fill the schema.

## Security notes

- The uploaded file is treated as untrusted evidence: no HTML, scripts,
  or attachment content is ever executed — only parsed as data.
- No outbound network requests are made anywhere in this stage.
- Access logs (uvicorn) record method/path/status only, never the
  parsed email body or attachment content.
- CORS is restricted to `http://localhost:3000` (the local Next.js
  dev origin) — no wildcard.

## Tests

```bash
uv run pytest -v
```

Tests parse a real generated `.eml` fixture at
`tests/fixtures/sample.eml` (multipart, RFC 2047 encoded subject, an
attachment, and URLs in both the plain-text and HTML parts) — nothing
is asserted against fabricated JSON.

## Not implemented in this milestone

SPF/DKIM/DMARC, threat intelligence, ML, threat scoring, MITRE ATT&CK,
sandboxing, YARA, database integration, authentication. These are
later pipeline stages.
