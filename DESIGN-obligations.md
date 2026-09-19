# Obligations

A regulator's questions after an incident, and the half of them this answers.

Satisfies REQ-77.

## Contents

- [Recorded, never computed](#recorded-never-computed)
- [Three conflated facts](#three-conflated-facts)
- [Stored facts](#stored-facts)
- [Screen contents](#screen-contents)
- [Windows](#windows)
- [Not built](#not-built)
- [Limits](#limits)

## Recorded, never computed

| Ours | Theirs |
|---|---|
| The moment something became known here | Whether an obligation applies |
| What was known at that moment | When it falls due |
| Who was told, and when | Whether it was met |

| Rule | Reason |
|---|---|
| No interpretation is encoded | This is a general product installed by organizations in different places under different rules, each reading its own counsel. An interpretation here is one every deployment inherits and none chose, and it is wrong for most of them the day a rule is amended |
| The facts are the same everywhere | Which is why they are the half this holds |
| No screen states a verdict | None says an obligation applies, none reports one met, and no default encodes a jurisdiction's window |
| A deployment under no duty sees a record it does not use | The record costs nothing to hold and answers nothing on its own |

## Three conflated facts

| | What it is | Where it comes from |
|---|---|---|
| A vulnerability is exploited somewhere in the world | A property of the **issue** | A feed, through the scanner |
| A vulnerability applies to our product | A **triage outcome** | A person, through a claim |
| Our product is being exploited through it | An **incident** | A customer, a researcher, an investigation. No feed reports this |

| Rule | Reason |
|---|---|
| Only the third is a reportable event | It is also the one nothing computes |
| A feed's exploitation flag is evidence that an issue deserves attention | It is a statement about the world, and says nothing about whether this deployment's product was the thing exploited |
| The first and the third are kept apart in name as well as in meaning | Both are called exploited, both raise urgency, and one of them arrives automatically. Reading the first as the third is the failure this area exists to prevent |

## Stored facts

Facts about moments. The moment each describes is gone by the time anybody
asks, which is why they are stored rather than worked out again.

| | |
|---|---|
| That this product was exploited through an issue, here | Person-recorded, append-only, on any finding regardless of kind. An inherited flaw used against our product is the case, and it needs no flaw of our own |
| The moment it became known | What every window a deployment might be under counts from |
| That somebody outside was told | Who, when, and about what. The same shape as the record of an advisory going out |
| Clearing the exploitation record | An explicit human withdrawal, recorded. Never automatic, and never a side effect of a scan |

## Screen contents

> became aware 14:00 Tuesday, told ENISA 09:00 Wednesday

The times, the parties, and what was known. Whether that satisfied anything is
not the tool's answer to give, and a screen offering a verdict would offer one
this deployment's operator has better grounds to reach.

## Windows

| Rule | Reason |
|---|---|
| A deployment configures its own, and none ships as a default | A shipped window is an interpretation, which is the one thing this area refuses to encode |
| The clock runs from the moment something became known | It is not the remediation deadline and is not derived from it |
| The remediation computation is not reused | That deadline stops where nothing upstream would close the finding, which is exactly the population a flaw of our own falls into, so reuse leaves the obligation with no clock at all. `DESIGN-remediation.md` § Deadlines has why that rule is right where it is |

## Not built

The obligation surface: where the windows are watched, warned in advance, and
kept out of reach of anything bulk. This document records a decision that is
not yet implemented, which is the difference between a plan somebody can read
and a gap somebody rediscovers by clicking.

| Rule | Reason |
|---|---|
| It is not a filter over the overdue list | A missed remediation deadline has no counterparty and one of these does, so they are different surfaces |
| The failure to design against is an obligation rendering as row 4,782 | Among four thousand unpenalized hygiene findings |
| Hygiene deadlines stay soft | Correct as it is, and stated here so nobody hardens the wrong half |

## Limits

Nothing here is a compliance feature and none of it should be sold as one. The
record is a record. Two deployments with identical records can owe entirely
different things, and the difference lives outside this software.

The exploited-here record cannot be verified by anything. It is somebody's
statement that an incident happened, which is what makes it append-only and
what makes clearing it a deliberate act with a name attached. Nothing re-checks
it, because nothing could.

A regulation is named nowhere in the code, the configuration or the screens.
Naming one makes the record look like an answer to that regulation, which is
the claim this area refuses to make. The reasoning that a particular rule
prompted this work belongs in a commit message and in this paragraph, and
nowhere a deployment reads it as advice.
