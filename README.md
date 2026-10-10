# Secure notes lab

A coursework repository for defensive application security and computing ethics. It contains a small notes API, a cryptography lab that calls maintained libraries, and original study notes for threat modeling, OWASP-style risk categories, disclosure, and ethical AI.

This is a teaching example. **It is not a production-ready service.** Do not store real passwords, personal notes, or operational secrets in it. Do not expose it beyond your own machine.

The import package is `secure_notes`. The repository name is `umd-cs4821-security-ethics`.

## What you practice

* Validating requests and rejecting unexpected fields.
* Hashing passwords with Argon2id through `argon2-cffi`.
* Returning the same authentication error for an unknown user and a wrong password.
* Authorizing every note read and delete against the session's user id.
* Sending SQL parameters separately from SQL text.
* Returning generic errors that do not include a traceback or a submitted password.
* Loading the server secret from the environment.
* Setting response headers that match a local HTTP lab.
* Applying a documented single-process rate limiter.
* Writing audit events that have nowhere to put a password, a token, or a note body.
* Distinguishing encoding, hashing, salts, MACs, authenticated encryption, and signatures.

## What this repository leaves out

On purpose, there is no exploit code, no credential-theft tooling, no scanner, no malware, no persistence mechanism, and no guide to attacking a system you do not run. The study notes describe failures and the controls that address them. Cryptography is delegated to `cryptography`, `argon2-cffi`, and the Python standard library.

## Layout

```text
.
├── .github/workflows/ci.yml
├── docs/
│   ├── threat-model.md
│   ├── security-principles.md
│   ├── owasp-study-guide.md
│   ├── cryptography-basics.md
│   ├── responsible-disclosure.md
│   ├── ethical-ai.md
│   └── learning-log.md
├── src/secure_notes/
├── tests/
├── pyproject.toml
├── README.md
└── COMMIT_MESSAGE.md
```

| Document | What it is for |
| --- | --- |
| [docs/threat-model.md](docs/threat-model.md) | STRIDE model of this lab: assets, boundaries, actors, controls, residual risk |
| [docs/security-principles.md](docs/security-principles.md) | Design habits the code is meant to show |
| [docs/owasp-study-guide.md](docs/owasp-study-guide.md) | Original course notes on major web risk categories |
| [docs/cryptography-basics.md](docs/cryptography-basics.md) | How the lab separates hash, salt, MAC, encryption, and signature |
| [docs/responsible-disclosure.md](docs/responsible-disclosure.md) | How to report a defect in this project |
| [docs/ethical-ai.md](docs/ethical-ai.md) | Privacy, consent, provenance, harm, oversight, retention, incidents |
| [docs/learning-log.md](docs/learning-log.md) | A log of what the lab does and does not prove |

## Run the lab

Requires Python 3.12.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
export NOTES_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m secure_notes.main
```

The server listens on `127.0.0.1:8000` and speaks plain HTTP. Generate a new secret for each shell you start. Do not commit it, and do not reuse a secret from another system.

Optional environment variables:

| Variable | Default | Role |
| --- | --- | --- |
| `NOTES_SECRET_KEY` | none; startup fails | HMAC key for stored bearer-token identifiers |
| `NOTES_DATABASE_PATH` | `notes-lab.db` | SQLite file. Tests use `:memory:` |
| `NOTES_TOKEN_TTL_SECONDS` | `3600` | Session lifetime |
| `NOTES_RATE_LIMIT_REQUESTS` | `30` | Login and register calls per window |
| `NOTES_RATE_LIMIT_WINDOW_SECONDS` | `60` | Window length |

`notes-lab.db` holds plaintext notes and password hashes. It is gitignored. Delete it when you are done with a session.

## API

Interactive OpenAPI pages are disabled so the process does not publish a second map of itself. These are the routes:

| Method | Path | Auth | Behavior |
| --- | --- | --- | --- |
| `GET` | `/health` | no | Liveness check |
| `POST` | `/auth/register` | no | Create an account. Duplicate names get a generic refusal |
| `POST` | `/auth/login` | no | Return a bearer token, or `Invalid credentials` |
| `POST` | `/notes` | bearer | Create a note owned by the session user |
| `GET` | `/notes` | bearer | List only that user's notes |
| `GET` | `/notes/{id}` | bearer | Read one note, or `Note not found` |
| `DELETE` | `/notes/{id}` | bearer | Delete one note owned by the session user |

Usernames are 3–32 characters from `[A-Za-z0-9_]`. Passwords are 12–128 characters. The password is hashed and is not returned. A note's owner is the session user; a body field named `owner_id` is rejected.

Example, against a server you just started:

```bash
curl -s -X POST http://127.0.0.1:8000/auth/register \
  -H 'content-type: application/json' \
  -d '{"username":"ada","password":"correct-horse-battery"}'
```

Use a throwaway password. Login returns a token. Send it as `Authorization: Bearer <token>`. The token is not stored in the database; an HMAC of it is.

## Cryptography lab

`secure_notes.crypto_lab` is a set of functions, not a network service. A short session:

```python
from secure_notes.crypto_lab import decrypt_aes_gcm, encrypt_aes_gcm, generate_aes_key

key = generate_aes_key()
sealed = encrypt_aes_gcm(key, b"lab note", b"notes-lab")
print(decrypt_aes_gcm(key, sealed, b"notes-lab"))
```

Read [docs/cryptography-basics.md](docs/cryptography-basics.md) before treating any of those functions as a general recipe. The salt helper is not a password hash. Base64 is not encryption. The notes table does not encrypt bodies.

## Quality gates

From the repository root, with the development extra installed:

```bash
ruff check .
ruff format --check .
mypy
pytest
pip-audit
```

CI runs the same steps on Python 3.12. `pip-audit` inspects the environment you installed. A clean run means that tool did not report a known advisory on that day. It does not certify the lab for production.

## Remaining risks

The threat model states these in full. The short version:

* Plaintext notes and password hashes live in SQLite. Anyone with the file can read them. The API's owner checks do not apply to the file.
* There is no TLS. The process is for loopback coursework.
* Sessions are bearer tokens. There is no second factor and no logout route. Expiry is the lab's session end.
* The rate limiter counts inside one process, resets on restart, and ignores `X-Forwarded-For` because that header is client-controlled.
* The audit log shares the database with the notes. It can be edited by anyone who can edit the file. It is not a remote monitoring system.
* Redaction removes known secret fields and `Bearer` spellings. It cannot recognize an arbitrary secret pasted into a new log message.
* Argon2id is configured at a published minimum profile, not benchmarked for a particular server.
* Dependency advisories move. Re-run `pip-audit` when you update.
* Passing tests show that the included checks still hold. They do not show that every future route will.

If you believe a control does not do what this document says, use [docs/responsible-disclosure.md](docs/responsible-disclosure.md). Demonstrate it on your own process.

## License

MIT. See [LICENSE](LICENSE).
