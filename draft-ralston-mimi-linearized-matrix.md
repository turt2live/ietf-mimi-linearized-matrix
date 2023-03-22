---
title: "Linearized Matrix API"
abbrev: "Linearized Matrix API"
category: std

docname: draft-ralston-mimi-linearized-matrix-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "More Instant Messaging Interoperability"
keyword:
 - matrix
 - linearized
 - interoperability
 - messaging
 - mimi
venue:
  group: "More Instant Messaging Interoperability"
  type: "Working Group"
  mail: "mimi@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mimi/"
  github: "turt2live/ietf-mimi-linearized-matrix"
  latest: "https://turt2live.github.io/ietf-mimi-linearized-matrix/draft-ralston-mimi-linearized-matrix.html"

author:
 -
    fullname: Travis Ralston
    organization: The Matrix.org Foundation C.I.C.
    email: travisr@matrix.org

normative:

informative:


--- abstract

Matrix is an existing openly specified decentralized secure communications protocol
able to provide a framework for instant messaging interoperability. Matrix rooms
currently use a Directed Acyclic Graph (DAG) for persisting events/messages. Servers
broadcast their changes to the DAG to every other server in order to create new events.

This model provides excellent decentralization characteristics, however is complex
when aiming to adopt Matrix as an interoperable chat protocol, such as with the emergence
of the European Union's Digital Markets Act (DMA).

This document explores an API surface for Matrix which knowingly trades some of the
decentralization aspects for ease of interoperability at a per-room level. We call this
API surface "Linearized Matrix".


--- middle

# Introduction

At a high level, rooms using Linearized Matrix have a single server which owns that room.
The owner can change, but will typically be the server which created the room. All other
servers are known as participating servers and call the owner server to send events. The
owner server is then responsible for informing all the other servers of any changes/messages
in the room.

Many aspects for how Matrix works as an interoperable messaging framework is described by
{{!I-D.ralston-mimi-matrix-framework}}. This document replaces the eventual consistency model,
federation API, and DAG-related features of the framework document by presenting a simpler
interface for interacting with Matrix rooms, without being incompatible with those same
replaced components.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO: Security
* We sign events to prevent the owner server lying.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
