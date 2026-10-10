# Learning log

A running record of what this lab is teaching and what it is deliberately not solving. Add an entry when a concept becomes concrete in code or when a review changes your mind. Entries should name the artifact (a test, a function, a doc section), not only the feeling that the topic is important.

Date format is ISO 8601. Keep secrets, tokens, and note contents out of the log the same way the audit table does.

## How to add an entry

```markdown
## YYYY-MM-DD — short title

- Observation: what the code or the reading actually does.
- Evidence: file, test, or request you can point to.
- Limit: what this does not prove.
- Next question: what you would need to learn to close that limit.
```

## 2026-10-10 — Lab built as a defensive refresher

- Observation: The notes API refuses to start without `NOTES_SECRET_KEY`, stores Argon2id password hashes, and returns one login failure body for an unknown user and a wrong password. Note routes take the owner from the session. Queries bind parameters. Audit rows have no column for a password, a token, or a note body. The cryptography module demonstrates hash, salt, HMAC, AES-256-GCM, and Ed25519 by calling libraries, and the tests flip a byte of each authenticator.
- Evidence: `src/secure_notes/passwords.py`, `src/secure_notes/service.py`, `src/secure_notes/crypto_lab.py`, `tests/test_authorization.py`, `tests/test_crypto_lab.py`, `tests/test_redaction.py`, `tests/test_sql_input.py`.
- Limit: The suite does not make the lab production-ready. Notes are plaintext in SQLite, there is no TLS, the rate limiter is single-process, and a person with the database file bypasses the API. Those limits are written in `docs/threat-model.md` so they are not mistaken for solved problems.
- Next question: If notes were encrypted at rest, where would the key live, who could rotate it, and which new log lines might capture plaintext before encryption?

## 2026-10-10 — Access control is a product decision, not a status code

- Observation: A foreign note and a missing note share the response "Note not found". That hides existence from another student. It also hides it from a client who mistyped an id and might have preferred a clear 403. The lab chooses the uniform 404 and records the choice.
- Evidence: `NotesService.get_note` and `tests/test_authorization.py`.
- Limit: Uniform responses do not stop a person who can read the SQLite file. They also do not, by themselves, prove there is no timing difference between the two cases.
- Next question: Which new field, if it were added to the error body, would undo the uniform response?

## 2026-10-10 — Words that are not interchangeable

- Observation: Base64 reverses without a key. SHA-256 is deterministic and has no key. A salt changes a digest and is not secret. HMAC detects change and does not hide the message. AES-256-GCM hides the message and detects change, including associated data. Ed25519 lets a public key check a signature without holding the private key. Password storage is Argon2id, not the salt demonstration.
- Evidence: `docs/cryptography-basics.md` and `tests/test_crypto_lab.py`.
- Limit: Being able to name the operation is not the same as being able to design a key hierarchy. The notes table is still plaintext because that second problem was not smuggled into the demo.
- Next question: Why can a verifier who holds an HMAC key also forge, while a verifier who holds only an Ed25519 public key cannot?

## 2026-10-10 — Ethics constraints before a model exists

- Observation: The repository states privacy, consent, provenance, representational harm, explainability, human oversight, evaluation limits, retention, and incident reporting before any model is attached. The current audit log already refuses note bodies, which is the retention rule a later summarizer would be tempted to break.
- Evidence: `docs/ethical-ai.md`, `docs/responsible-disclosure.md`, `audit_events` in `src/secure_notes/database.py`.
- Limit: A written policy does not bind a future pull request unless review uses it. The document says a model call needs a design change, not a drive-by client.
- Next question: What would a consent sentence say, in plain language, if a later assignment wanted to summarize a note with a hosted model?
