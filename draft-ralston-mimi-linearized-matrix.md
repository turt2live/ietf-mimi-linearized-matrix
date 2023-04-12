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
 -
    fullname: Matthew Hodgson
    organization: The Matrix.org Foundation C.I.C.
    email: matthew@matrix.org

normative:

informative:
  MSC3995:
    target: https://github.com/matrix-org/matrix-spec-proposals/pull/3995
    title: "MSC3995: [WIP] Linearized Matrix"
    date: 2023
    author:
       - fullname: Travis Ralston
         organization: The Matrix.org Foundation C.I.C.
         email: travisr@matrix.org

--- abstract

Matrix is an existing openly specified decentralized secure communications protocol
able to provide a framework for instant messaging interoperability. With changes to
how Matrix handles rooms, the protocol becomes easily suited for messaging interoperability
usecases.

This document explores "Linearized Matrix": the modified room model still backed by
Matrix.

--- middle

# Introduction

Alongside messaging, Matrix operates as an openly federated communications protocol for
VoIP, IoT, and more. The existing Matrix network uses fully decentralized access control
within rooms (conversations) and is highly extensible in its structure. These features
are not critically important to a strict focus on messaging interoperability, however.

This document describes "Linearized Matrix": an API surface on top of Matrix's existing
room model. This document does *not* explore how to interconnect Linearized Matrix with
the existing Matrix room model - interested readers may wish to review MSC3995 {{MSC3995}}
within the Matrix Specification process.

# Conventions and Definitions

This document uses {{!I-D.ralston-mimi-terminology}} where possible.

This document additionally uses the following definitions:

* **Room**: Synonymous with "conversation" from I-D.ralston-mimi-terminology.
* **Room Member**: Synonymous with "conversation member" from I-D.ralston-mimi-terminology.
* **State Event**: Synonymous with "conversation property" from I-D.ralston-mimi-terminology.
  A state event is a subclass of an event.

# Architecture

~~~ aasvg
       .------------.                                  .------------.
      |   Client A   |                                |   Client B   |
       '------------'                                  '------------'
        ^          |                                    ^          |
        |  events  |  Client-Server API                 |  events  |
        |          V                                    |          V
    +------------------+                            +------------------+
    |                  |----------( events )------->|                  |
    | Provider/Server  |                            | Provider/Server  |
    |        A         |<---------( events )--------|        B         |
    +------------------+     Server-Server API      +------------------+
          |     ^
          |     |                                   +------------------+
          |     +-----------------( events )--------|                  |
          |                                         | Provider/Server  |
          +-----------------------( events )------->|        C         |
                                                    +------------------+
                                                        ^          |
                                                        |  events  |
                                                        |          V
                                                       .------------.
                                                      |   Client C   |
                                                       '------------'
~~~



# Security Considerations

**TODO**: Expand upon this section.

As discussed in the Event Signing section, we ensure servers are not able to spoof events.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

Thank you to the Matrix Spec Core Team (SCT), and in particular Richard van der Hoff, for
exploring how Matrix rooms could be represented as a linear structure, leading to this document.
