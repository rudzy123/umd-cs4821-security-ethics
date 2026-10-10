# Security principles

These are the design rules the notes lab is meant to make concrete. Each one is a habit: where the decision shows up, and what failure looks like when the habit is skipped.

## Fail closed

If the server secret is missing, the process refuses to start. If a note id is not a UUID, the note is treated as unavailable. If an exception has no handler that understands it, the client receives a fixed internal-error message. The unsafe alternative is to continue with an empty secret, a guessed owner, or a stack trace.

## Deny by default

Every note route requires a bearer token. The token is checked before the handler reads or writes a note. There is no "public note" flag. A new route is unauthorized until someone adds a check on purpose.

## Complete mediation

Ownership is checked on read and on delete, not only on create. The list query is restricted to the caller's id. Delete requires both the note id and the owner id in the same statement, so a missing check in Python is not the only line of defense. One strong check on the way in does not cover a second code path.

## Least privilege

The client never receives the password hash, the server secret, or another user's notes. The audit log is not an HTTP resource. The process binds to `127.0.0.1`. Interactive API docs are off. The database account is just the local file: this lab cannot do better than the operating system here, and the README says so.

## Least data

Passwords exist in memory long enough to hash them, then the hash is what gets stored. Bearer tokens are stored only as an HMAC. Audit events have a fixed set of columns: time, event type, outcome, actor id, resource type, resource id. There is no message column that a later change could fill with a note body.

Validation errors name the field and the rule. They do not repeat the submitted password.

## Secure defaults

Argon2id uses an explicit memory-hard profile, not a fast hash. Extra JSON fields are rejected, so a client cannot smuggle `owner_id`. CORS is not enabled. `X-Forwarded-For` is not consulted. Security headers on responses tell browsers not to sniff content, frame the response, or cache it.

HSTS is not set, because this server does not speak TLS. A default that the deployment cannot honor is not a secure default.

## Defense in depth

Cross-user access is blocked by the session check and by the owner column in the query. Secret leakage is blocked by not logging the value and by a redaction filter for known fields. SQL injection is blocked by placeholders and by treating a suspicious string as an ordinary title in the tests. Any one of these can be bypassed by a later edit. The pair is what makes the edit obvious in review.

## Do not trust the client

The owner, the role, and the token lifetime come from the server. The client supplies a username, a password, and note text. Note text is data. It is not a statement, a template, or an instruction to the database.

## Separate secrets from source

`NOTES_SECRET_KEY` is read from the environment. The repository does not contain a usable default. Tests pass a value that is labeled as a lab secret and is not used as a production key. A `.env` file is gitignored. None of that helps if a real secret is pasted into a ticket.

## Use maintained cryptography

Password hashing calls Argon2id through `argon2-cffi`. The cryptography lab calls SHA-256, HMAC, AES-256-GCM, and Ed25519 through the `cryptography` package, and draws random bytes through `secrets`. The standard-library `hmac` module keys the stored token identifier. This repository does not contain an AES round function, a hash compression function, or a signature equation.

## Prefer boring, small features

There is no search box, no HTML renderer, no outbound URL fetch, and no plugin hook. Each of those is a common source of injection or server-side request problems. The lab keeps the entry points that the lessons need.

## Psychological acceptability

Passwords have a minimum length and a maximum length. The maximum exists so an enormous field cannot be used as a cheap way to waste hashing time, and so people are not invited to paste an entire document into the password box. Error text is short enough to act on ("Invalid credentials") without becoming a hint about which half of the pair was wrong.

Registration uses the same idea: a duplicate username does not get a message that says the name is taken. That choice reduces account enumeration and makes the form slightly harder to use. The tradeoff is documented rather than hidden.

## Build the check you can re-run

A principle that exists only in this document will drift. The suite asserts different hashes for one password, identical failure bodies for bad logins, cross-user denial, tampered cryptographic values, malformed input, redaction, and SQL-like strings stored as data. When a change breaks one of those, the run fails in public.

## What these principles do not do

They do not make the lab a production notes product. They do not replace threat modeling, code review, or a decision about whether a feature should exist. They give a reviewer a vocabulary for saying what a change just violated.
