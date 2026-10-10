# Ethical AI

This note is for engineers who may later attach a model to a system like the notes lab: a summarizer, a search ranker, a classifier that flags "sensitive" notes, or a coding assistant trained on student work. The notes API does not call a model. The duties below start when someone proposes that feature, and most of them apply to ordinary data handling even when no model is involved.

Ethics here is not a personality for the model. It is a set of constraints on collection, purpose, evaluation, and what happens when the system is wrong.

## Privacy

A note body is personal data in the ordinary sense: it can contain health details, finances, names of other people, or writing the author has not agreed to show anyone. The lab already treats the body as something the audit log must not store. Sending that body to a model is a new disclosure. The recipient might be a vendor, a campus GPU, a log pipeline, or a training set that outlives the course.

Minimize what leaves the process. A summary feature that needs the body still does not need the password, the bearer token, or the server secret. Those are separate categories of secret, and a model prompt is a bad place to discover that a client library logs prompts by default.

If the model runs on someone else's computer, the threat model gains a trust boundary. Write that boundary down before enabling the call. If you cannot name who receives the text and how long they keep it, you do not yet have a design.

## Informed consent

Consent is a specific agreement to a specific use, given by a person who can refuse without a hidden penalty. A checkbox buried in a course platform, or a default of "on," is not that.

For a class tool, say in plain language:

* What text will be sent, and to whom.
* Whether the text will be stored, and for how long.
* Whether it will be used to train or evaluate a model.
* What the person can do instead, including using the notes API with the feature left off.
* How to withdraw, and what withdrawal does to copies already made.

Consent to store a note so the author can read it later is not consent to summarize it, grade it, or include it in a dataset. Those are new purposes. If the person is a student and the requester is an instructor, the power difference matters: agreement is harder to treat as voluntary when refusal affects a grade. Do not make the model feature a condition of submitting the assignment.

People who are mentioned inside a note did not consent just because the author did. A summarizer does not fix that. Avoid features that broadcast or classify other people's information.

## Dataset provenance

Provenance is the record of where training or evaluation data came from and what you are allowed to do with it. "We had a file" is not provenance.

Before a dataset is used, record:

* Who created the records, and whether they were told about this use.
* The legal and course-policy basis for using them. Course policy may be stricter than the law. Follow the stricter rule.
* What was removed (direct identifiers, secrets, other people's data) and what remains.
* The commit or checksum of the dataset actually used, so an evaluation can be repeated.
* Whether any notes from this lab, any student submissions, or any scraped text are included. Scraping does not create permission.

Do not train on the audit log, on passwords, or on tokens. Do not train on note bodies from this lab unless every author whose text is included agreed to that use and you can show the agreement. A synthetic fixture you wrote yourself is the clean default for coursework.

If provenance is incomplete, do not "use it just for evaluation." Evaluation copies are still copies.

## Bias and representational harm

Models repeat patterns in their data, including patterns of neglect and stereotype. Harm shows up when a feature treats people differently or describes them in a way that singles out a group.

Examples that could attach to a notes tool:

* A "sensitive content" classifier that flags writing about disability, religion, or identity and then hides it from the author or shows it to an administrator.
* A summary that drops details related to a group the training data rarely represented, so the summary is confidently incomplete.
* A writing assistant that "corrects" dialect or a name into a more common form.

Representational harm is not only a wrong label on a benchmark. It is a person being misdescribed, excluded, or exposed. A small course project can cause that if it is pointed at real notes.

Look for it on purpose. Choose evaluation examples that include groups and writing styles the designers do not personally share. Read errors, not only averages. If a feature cannot be shown to behave acceptably on those examples, do not ship it with a disclaimer in the README. A disclaimer is not a control.

## Explainability

People affected by a suggestion deserve a description they can check. "The model said so" is not a description.

For a summary, show the source note next to the summary and say that the summary can omit or invent details. For a classifier, say what the label means in product language and what it will change (nothing, a highlight, a block). Do not present a probability as a reason. If you cannot explain what input the output was based on, do not use the output to grant or deny access. Access control in this lab stays with the owner check, which a human can read. A model score must not become `owner_id`.

Explainability also applies to the engineers. Keep the prompt or the model version with the change that enabled it, so a later reviewer can see what the system was asked to do.

## Human oversight

Oversight means a person can notice a bad outcome and stop it, and their decision is the one that counts. A dashboard nobody is assigned to watch is not oversight.

Practical shape for a course project:

* A person turns the feature on for their own notes. It does not run on every note in the database.
* The person can edit or discard the model output. The stored note does not change unless they save it.
* No automated action deletes a note, shares it, or files a conduct report.
* Someone is named as the contact when the feature misbehaves, and that path is the same kind of path as `docs/responsible-disclosure.md`.

If the oversight step is skipped whenever the model is confident, the oversight does not exist at the moment it is most needed. High confidence is not a substitute for the check.

## Evaluation limitations

An evaluation measures the cases you wrote down. It does not measure the cases you did not imagine. A high score on a summary rubric can sit next to a failure to keep data private, because the rubric never asked.

Write down the limits every time you report a number:

* How many examples, who wrote them, and what was excluded.
* What "good" means (faithful to the note, short, nothing else).
* Which harms were not measured. Privacy leakage, bias, and prompt injection of instructions hidden in a note are different tests. A quality score is not those tests.
* The model identifier and the date. Results do not transfer silently to the next model.
* Whether the people designing the test are the only people represented in it.

Do not tune the feature on the same examples you use to claim it works. Hold some back, or say that you did not. Do not describe a classroom demo as a study of real users.

The notes lab's own tests have this shape of honesty: they show specific controls and the README says what they do not show. Model features need the same sentence.

## Data retention

Keep data for a stated purpose and a stated time, then delete it. "The disk is cheap" is not a purpose.

Decide, before collection:

* How long a prompt, a completion, and a log line are kept.
* Where they are kept, and who can read them.
* How deletion works, including vendor copies and backups if any exist.
* What is retained after a person withdraws consent. The default should be to delete the content and keep only a minimal record that a request was honored, if a record is required at all.

The lab's audit log retains actor ids and note ids, not note bodies, because the purpose is a security record. That purpose does not justify retaining the body "in case a model needs it later." A new purpose needs a new decision and, where the note says so, new consent.

Do not copy the SQLite file into a notebook, a chat with a model, or a slide. That copy will not follow the retention rule you wrote for the server.

## Incident reporting

An incident is an event where the system exposed data, took an action it should not have taken, or was found to be biased or misleading in a way that affected a person. A near miss counts when the only thing that prevented harm was luck.

Report it while the details are fresh. Use the channel in `docs/responsible-disclosure.md` for defects in this repository, and the course's incident channel for anything that involves real personal data. Include:

* What happened, when, and what data was involved, described without pasting the data.
* Who is affected, as far as you know.
* What you have already done (feature off, copies deleted, secret rotated).
* What you are unsure about. Uncertainty belongs in the report, not in a delay.

Tell affected people what they need in order to protect themselves, in language that is specific. "We take privacy seriously" is not a report. If you do not know whether their note left the machine, say that, and say what you are doing to find out.

Afterward, write down the cause and the change that makes the same path harder. A model feature that cannot be turned off during an incident was not ready to turn on.

## A boundary for this repository

Do not add a model call, a dataset of real notes, or a classifier that gates access as a drive-by improvement. Propose it as a design change with provenance, consent, retention, an evaluation that names its limits, and a way to shut it off. The secure-notes API is the practice ground for those habits: small data, explicit owners, logs that refuse secrets, and a written residual risk.
