# Responsible disclosure

This document is the reporting practice for this coursework repository. It is not legal advice, and it is not permission to test systems that belong to someone else.

## What this practice is for

A vulnerability report is a request that a maintainer fix a defect. The goal is a smaller chance that the next person is harmed by the same bug. Surprise publication, access to other people's data, and proof that requires damaging a system work against that goal.

The notes API is a local teaching process. It is not a production service and it is not hosted for you. "I found a bug in the lab" means a bug in this code, demonstrated against a process you started yourself.

## Scope

In scope:

* Defects in this repository's application code, tests, or documented security claims.
* A control that does not do what `docs/threat-model.md` or the README says it does.
* A dependency issue you can point to with a public advisory, without writing an exploit.

Out of scope:

* The University of Maryland network, campus single sign-on, or any system this repository does not run.
* Social engineering against classmates, instructors, or maintainers.
* Denial-of-service demonstrations, including against the local lab if they would disrupt a shared machine.
* Findings that only restate the residual risks already written down (plaintext notes in SQLite, no TLS, in-memory rate limits, no second factor). Those are known limits. A report that adds a new consequence is still welcome.

If you are unsure whether a target is in scope, stop and ask before you test.

## How to test

Use your own checkout and a database you created. Bind to localhost the way the README describes. Use test accounts and test notes. Do not put real passwords, student records, or someone else's private writing into the lab.

Prefer the smallest demonstration that shows the defect: a failing test, a request and a response, or a short description of the code path. A demonstration that reads or changes data should use data you planted for the purpose.

Stop when you can show the issue. Do not pivot into other accounts, and do not keep the data you happened to see. If a test unexpectedly returns another person's note, that is the finding. Close it there.

## How to report

Send the report to the course staff or the repository maintainer through the channel they gave you. If no channel was named, open a private course message rather than a public issue, and ask where they want security reports to go.

Include:

* A one-sentence description of the impact.
* The version or commit you ran.
* The route or function involved.
* The steps you took on your own instance, including any test account names you created.
* What you expected, based on the threat model or the code, and what happened instead.
* Whether you believe any data other than your own test data was exposed. For this local lab, say so explicitly if the answer is no.

Omit passwords, bearer tokens, the server secret, and note contents. Refer to them as "the test password" or "the note body" unless the content itself is the bug and it is fake data you created. Do not include a proof-of-concept that is aimed at a host you do not control.

If you are filing a public issue because the maintainer asked for that, keep the same omissions. A public issue is a bad place for a working attack against a system that is still unfixed. This lab is local, which lowers that risk, and the habit is still worth practicing.

## What you can expect

This is a class repository, not a vendor program. There is no paid bounty and no promised timeline. A reasonable maintainer response is to confirm the report, say whether it matches a known residual risk, and either fix it or document why it remains.

You will not be asked to provide an exploit against a real target as a condition of being heard.

## Coordination

Give the maintainer time to read the report before you describe it publicly. A class discussion can be a good place to learn from a defect after the instructor has agreed the example is appropriate. Publishing a classmate's data, or a secret you found in a configuration file, is not a class discussion.

If the defect is in an upstream library rather than in this repository, report it to that project through their published security contact. Quote their policy. Do not file their embargoed details in this repository's public history.

## Accidents

If you copied a real secret into a commit, a log, or a note, treat that as an incident: revoke or rotate the secret, remove it from the working copy, and tell the person who owns it. Rewriting git history is a maintainer decision because it affects everyone who already fetched the repository. Do not push a history rewrite on your own.

If test data included personal information about a real person, delete it and say so in the report. `docs/ethical-ai.md` covers the same duty when the data was collected for a model rather than for a bug report.

## Behavior that is not disclosure

The following are outside this practice, even if they are labeled as research:

* Scanning or signing in to systems you were not given.
* Using a finding to read other students' notes, email, or accounts.
* Holding a report back in exchange for a grade, money, or access.
* Adding offensive tooling to this repository so the bug is easier to repeat against other hosts.

The project constraints match that boundary. This repository teaches the defensive control and the report. It does not ship the attack.
