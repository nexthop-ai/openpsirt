# Obligations

What a regulator asks for after an incident, and which half of it is ours to
answer.

Satisfies REQ-77.

## Contents

- [Recorded, never computed](#recorded-never-computed)
- [Three facts that get conflated](#three-facts-that-get-conflated)
- [What is stored](#what-is-stored)
- [What a screen shows](#what-a-screen-shows)
- [Windows](#windows)
- [Not built](#not-built)
- [Limits](#limits)

## Recorded, never computed

| Ours | Theirs |
|---|---|
| When something became known here | Whether an obligation applies |
| What was known at that moment | When it falls due |
| Who was told, and when | Whether it was met |

The deployment is a general product, installed by organizations in different
places under different rules, each reading its own counsel. An interpretation
encoded here is one every deployment inherits and none of them chose, and it is
wrong for most of them the day a rule is amended. The facts are the same for all
of them.

Nothing here decides anything. No screen says an obligation applies, none
reports one was met, and no default encodes a jurisdiction's window. A
deployment that must report something reads the record and answers; a deployment
under no such duty sees a record it does not use.

## Three facts that get conflated

| | What it is | Where it comes from |
|---|---|---|
| A vulnerability is exploited somewhere in the world | A property of the **issue** | A feed, through the scanner |
| A vulnerability applies to our product | A **triage outcome** | A person, through a claim |
| **Our product is being exploited through it** | An **incident** | A customer, a researcher, an investigation. No feed reports this |

Only the third is a reportable event, and it is the one nothing computes. A
feed's exploitation flag is a statement about the world that says nothing about
whether this deployment's product was the thing exploited — so it is evidence
that an issue deserves attention, and it is not evidence that anything happened
here.

Reading the first as the third is the failure this area exists to prevent, and
it is an easy one: both are called "exploited", both raise urgency, and one of
them arrives automatically. They are kept apart in name as well as in meaning,
so that no report can read them as one.

## What is stored

Facts about moments, which is why they are stored rather than worked out again:
the moment they describe is gone by the time anybody asks.

| | |
|---|---|
| That this product was exploited through an issue, here | Person-recorded, append-only, on any finding regardless of kind — an inherited flaw used against our product is the case, and it needs no flaw of our own |
| When it became known | Which is what every window a deployment might be under counts from |
| That somebody outside was told | Who, when, and about what. The same shape as the record of an advisory going out |
| Clearing the exploitation record | An explicit human withdrawal, recorded. Never automatic, and never a side effect of a scan |

## What a screen shows

> became aware 14:00 Tuesday, told ENISA 09:00 Wednesday

The times, the parties, and what was known. Whether that satisfied anything is
not the tool's answer to give, and a screen that offered a verdict would be
offering one this deployment's operator has better grounds to reach.

## Windows

A deployment configures its own, and **none ships as a default**. A shipped
window is an interpretation, and the one thing this area refuses to encode.

An obligation's clock runs from when something became known. It is not the
remediation deadline and is not derived from it: a remediation deadline stops
where nothing upstream would close the finding, which is exactly the population a
flaw of our own falls into. Reusing that computation would silently leave the
obligation with no clock at all — see `DESIGN-remediation.md` § Deadlines for
why that rule is right where it is.

## Not built

The obligation surface itself: where the windows are watched, warned in advance,
and kept out of reach of anything bulk. **This document describes a decision
that is recorded and not yet implemented**, which is the difference between a
plan somebody can read and a gap somebody rediscovers by clicking.

What it will not be is a filter over the overdue list. A remediation deadline
that is missed has no counterparty, and one of these does — so they are
different surfaces, and the failure to design against is an obligation rendering
as row 4,782 among four thousand unpenalized hygiene findings. The converse is
worth stating so nobody optimizes the wrong half: hygiene deadlines being soft is
correct and needs no hardening.

## Limits

Nothing here is a compliance feature and none of it should be sold as one.
The record is a record. Two deployments with identical records can owe entirely
different things, and the difference lives outside this software.

The exploited-here record cannot be verified by anything. It is somebody's
statement that an incident happened, which is what makes it append-only and what
makes clearing it a deliberate act with a name attached. Nothing re-checks it,
because nothing could.

A regulation is named nowhere in the code, the configuration or the screens.
Naming one makes the record look like an answer to that regulation, which is the
claim this area refuses to make. The reasoning that a particular rule prompted
this work belongs in a commit message and in this paragraph, and nowhere a
deployment reads it as advice.
