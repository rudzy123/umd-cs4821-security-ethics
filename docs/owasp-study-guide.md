# OWASP study guide

This guide is course wording for the failure modes commonly taught through the OWASP Top 10 (2021 edition). The category names are theirs. The definitions, examples, and tests below were written for this lab and are not a copy of the OWASP text. Rankings change. The skill that transfers is recognizing the failure mode in a design you are about to ship.

Each section has a definition, a safe illustration, defensive controls, and a way to test. Illustrations describe the lab's own behavior or a design choice. They are not procedures for attacking a system.

## Broken access control

**Definition.** The application fails to enforce who may use a function or a record. The usual shape is an identifier the client supplies: a note id, a file name, or an account id. Authentication answered "who is this?" and then nobody asked "may this person touch that object?"

**Safe illustration.** In this lab, `GET /notes/{id}` loads the note and returns it only when `owner_id` equals the user id on the session. A different signed-in user receives the same "Note not found" body as they would for an id that does not exist. `DELETE` includes the owner id in the same SQL predicate. The create body has no owner field; an extra `owner_id` is rejected.

**Defensive controls.** Deny by default. Check the object on every route, including updates and deletes. Prefer queries that include the owner, so a forgotten `if` is not the only control. Return a uniform response when hiding existence matters. Do not take roles or ownership from the client. Add a test for each neighboring user, not only for the happy path.

**Testing approach.** Create two accounts. Store an object as the first. As the second, list, read, and delete that id. Compare the read of a foreign id with the read of a random UUID. Repeat with no `Authorization` header. Review new routes by asking where the owner id comes from.

## Cryptographic failures

**Definition.** Data that needed a confidentiality or integrity property is stored or sent without one, or a primitive is used for the wrong job. Fast hashes for passwords, encryption without an integrity check, and a secret committed next to the code are all this category. So is treating base64 as if it were encryption.

**Safe illustration.** Passwords are stored with Argon2id. Two hashes of the same password differ because the library embeds a salt. Bearer tokens are random and only their HMAC is stored. The cryptography lab uses AES-256-GCM and Ed25519 from the `cryptography` package, and it shows that base64 round-trips without a key. Note rows themselves are plaintext. That is called out as residual risk, not disguised as encryption.

**Defensive controls.** Use a maintained library. Pick the primitive that matches the goal: password hashing, keyed MAC, authenticated encryption, or signature. Generate keys and tokens with `secrets`. Keep secrets in the environment. State, in writing, which assets are not encrypted.

**Testing approach.** Assert that equal passwords do not produce equal stored hashes and that the password is not a substring of the hash. Flip a byte of a MAC tag, a ciphertext, and a signature, and assert verification fails. Assert the process will not start without `NOTES_SECRET_KEY`.

## Injection

**Definition.** An interpreter treats attacker-controlled data as instructions. SQL is the familiar case. The same shape appears in shell commands, HTML, template engines, and header values. The defect is the confusion of data and code, not the presence of a particular character.

**Safe illustration.** Note titles and bodies are bound with `?` placeholders. A title whose characters resemble a SQL comment is stored and returned unchanged, and a later insert still succeeds. Note ids that are not UUIDs never reach the query as an identifier. The lab has no shell calls and no HTML renderer, which removes two interpreters rather than trying to escape them.

**Defensive controls.** Keep query text in the source and data in parameters. Use a fixed allow-list for identifiers such as sort columns if you ever add them. Encode on output for the context you are emitting (HTML, URL, header). Prefer APIs that do not invoke a shell. Do not add a search feature until the query is designed.

**Testing approach.** Submit punctuation and SQL-like phrases as field values. Assert the value round-trips and that later operations still work. Review diffs for f-strings or concatenation inside `execute`. Add a regression test when a reviewer finds a string that is being composed into a statement.

## Insecure design

**Definition.** The design cannot be patched into safety because the missing control was never a requirement. Examples: a password reset that trusts a guessable code, a "remember this device" feature with no threat model, or a notes app that adds public links without deciding what "public" means.

**Safe illustration.** This lab's design record is `docs/threat-model.md`. Registration does not reveal whether a username exists. There is no admin impersonation feature. The rate limiter is specified as a local teaching control, with its limits written down, instead of being described as if it were a global defense.

**Defensive controls.** Write the abuse case before the route. Choose the smallest feature that meets the learning goal. Record residual risk in the same change. Prefer deleting a risky requirement over adding a warning comment.

**Testing approach.** For each new user story, ask what a different signed-in user will try, what the error will reveal, and what lands in the log. If the answer is "we will handle that later," the design is not done. Trace those answers to a test or to an explicit residual-risk note.

## Security misconfiguration

**Definition.** The software is capable of a safe setup, but the running instance is not using it. Default secrets, open admin consoles, directory listings, stack traces, permissive CORS, and debug flags in production are typical.

**Safe illustration.** The lab will not boot with an empty server secret. Docs endpoints are off. CORS is not installed. Unhandled exceptions do not return a traceback. The development server binds to loopback. HSTS is omitted on purpose because TLS is not configured; pretending otherwise would be a misconfiguration of a different kind.

**Defensive controls.** Separate lab defaults from any shared deployment. Fail startup when a required secret is missing. Turn off debug and interactive docs on anything reachable by other people. Review framework defaults when you upgrade. Set browser headers that match the responses you actually serve.

**Testing approach.** Boot with the secret unset and expect a startup failure. Request a missing route and an unhandled error and read the body for pathnames or exception text. Inspect response headers, including the absence of `Access-Control-Allow-Origin: *`. Read the framework's release notes when dependencies move.

## Vulnerable and outdated components

**Definition.** The application trusts a library, and that library later has a known defect. The application code can be careful and still be exposed because the fix lives upstream.

**Safe illustration.** Direct dependencies are declared in `pyproject.toml` and installed from maintained projects: FastAPI, Pydantic, Argon2, and `cryptography`. The CI workflow runs `pip-audit` against the environment it just installed. The lockstep is "install, then audit," not a pasted screenshot of a clean run.

**Defensive controls.** Prefer libraries that are still maintained. Pin enough of the version to reproduce a lab, and update on purpose. Remove dependencies you do not call. Subscribe to the project's advisory channel. Rebuild and retest when an advisory arrives, rather than editing the advisory out of the log.

**Testing approach.** Run `pip-audit` in CI and locally after dependency changes. When it reports a finding, upgrade or replace the package and record the decision. Do not treat a silent environment (tool not installed) as a pass; the README says to run it when it is installed and not to claim a production review.

## Identification and authentication failures

**Definition.** The application is unsure who the caller is. Weak password storage, unlimited guessing, user enumeration, session ids in URLs, and tokens that never expire sit here. Broken access control assumes you know the caller and still authorize badly. This category is about the caller not being established in the first place.

**Safe illustration.** Registration stores Argon2id output. Login returns one message for an unknown user and a wrong password. The route is rate limited before the failure is returned. The session identifier is a random token sent in a header, not a URL. The database stores an HMAC of that token. Expired sessions are rejected with the same client message as an unknown token.

**Defensive controls.** Use a memory-hard password hash. Cap password length. Rate-limit credential attempts. Avoid stating which field was wrong. Rotate or expire sessions. Do not log the password or the token. Consider a second factor when the asset justifies the friction; this lab does not implement one, and the threat model says so.

**Testing approach.** Assert the two login failures match byte for byte. Assert a burst of failures eventually receives a uniform "too many requests" response that does not contain the attempted password. Decode a stored session row and confirm it is not the token the client received. Confirm a request with no token is rejected.

## Software and data integrity failures

**Definition.** The application trusts data or code that it did not authenticate. Examples include an unsigned update, a deserialization gadget, a dependency pulled from an unexpected source, and a token whose signature is not checked.

**Safe illustration.** The cryptography lab rejects a MAC, a GCM ciphertext, and an Ed25519 signature after a one-byte change. Bearer tokens are verified by recomputing an HMAC and looking that value up; the raw token is not accepted as a database key. The lab does not deserialize pickle and does not load plugins from the request.

**Defensive controls.** Verify signatures with the public key and MACs with the shared secret, using the library's compare function. Use authenticated encryption when you need confidentiality. Review dependency sources. Treat serialized objects from the client as data formats you parse, not as code you execute.

**Testing approach.** Flip a byte and assert failure, including associated data for AEAD. Add a test that a wrong key fails closed. In review, look for new parsers and for any `pickle`, `yaml.load`, or dynamic import fed by a request.

## Security logging and monitoring failures

**Definition.** The record of security-relevant actions is missing, is full of secrets, or cannot be trusted later. An event that logs the password is a disclosure bug wearing an audit costume. An event that is never written leaves the operator unable to tell what happened.

**Safe illustration.** Register, login, session rejection, note creation, note access, note deletion, and rate limiting write an audit row. The row has no column for a password, a token, or a note body. The logger runs a redaction filter for sensitive field names and for `Bearer` spellings. Users cannot download the audit log through the API. The threat model states that the log lives in the same SQLite file and can be edited by anyone who can edit the database.

**Defensive controls.** Decide the event list in advance. Log identifiers, not contents. Redact structured fields. Keep secrets out of exception messages that you log. Protect the log from the same principals the log is about. Review logs as part of an incident, which `docs/responsible-disclosure.md` and `docs/ethical-ai.md` both depend on.

**Testing approach.** Perform a login and a note write with distinctive markers. Assert those markers are absent from captured log lines and from every audit column. Assert a mapping that contains `password` is redacted before it is formatted. Review new `logger` calls in the diff.

## Server-side request forgery

**Definition.** The server fetches a URL, or opens a connection, that the client chose. The server's network position then becomes the client's. Internal administration pages, cloud metadata addresses, and other tenants are the usual impact. The client did not need to be able to route to them directly.

**Safe illustration.** This process does not make an outbound request. It has no "preview this link" feature and no webhook URL. That is the control: the feature is not there. A future "summarize the article at this URL" assignment would add this category on the day it is merged.

**Defensive controls.** Do not add a fetcher casually. If a course exercise needs one, allow only specific schemes and hosts, resolve and pin the address you checked, refuse link-local and metadata ranges, and keep the allow-list on the server. Do not send the server secret or the user's token to the remote host. Describe the new trust boundary in the threat model before writing the client.

**Testing approach.** Inventory every HTTP client, DNS lookup, and file path influenced by a request. For this repository, that inventory is empty on purpose. A review of a pull request that adds a client library should stop until the allow-list and the tests exist. Tests belong against the allow-list, using local fixtures, never against a third-party host.

## How to use this guide

When you add a feature, name the categories it touches and point to the control. If you cannot name a control, write the residual risk in `docs/threat-model.md` and in the README. A category with no control and no residual-risk note is an unfinished design.
