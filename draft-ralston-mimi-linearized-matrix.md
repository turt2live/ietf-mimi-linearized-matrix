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
  MxV10AuthRules:
    target: https://spec.matrix.org/v1.6/rooms/v10/#authorization-rules
    title: "Matrix Specification | v1.6 | Room Version 10 | Authorization Rules"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxV10PDUFormat:
    target: https://spec.matrix.org/v1.6/rooms/v10/#event-format-1
    title: "Matrix Specification | v1.6 | Room Version 10 | Event Format"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxContentHashCalculation:
    target: https://spec.matrix.org/v1.6/server-server-api/#calculating-the-content-hash-for-an-event
    title: "Matrix Specification | v1.6 | Federation API | Calculating the Content Hash"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxRedaction:
    target: https://spec.matrix.org/v1.6/client-server-api/#redactions
    title: "Matrix Specification | v1.6 | Client-Server API | Redaction Algorithm"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxCanonicalJSON:
    target: https://spec.matrix.org/v1.6/appendices/#canonical-json
    title: "Matrix Specification | v1.6 | Appendices | Canonical JSON"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxSigning:
    target: https://spec.matrix.org/v1.6/appendices/#signing-details
    title: "Matrix Specification | v1.6 | Appendices | Signing"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxRoomVersion10:
    target: https://spec.matrix.org/v1.6/rooms/v10
    title: "Matrix Specification | v1.6 | Room Version 10"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.
  MxSignatureValidation:
    target: https://spec.matrix.org/v1.6/server-server-api/#validating-hashes-and-signatures-on-received-events
    title: "Matrix Specification | v1.6 | Federation API | Validating Hashes and Signatures"
    date: 2023
    author:
      - org: The Matrix.org Foundation C.I.C.


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
federation API, and DAG-related features of the framework document by presenting rooms as a
single, flat, array of events, without being incompatible with those same replaced components.

This document does not currently define transport layer for the Linearized Matrix API, instead
focusing its efforts on the operational aspects of a room.

# Conventions and Definitions

<!--
{::boilerplate bcp14-tagged}
-->

This document additionally uses the following definitions:

* Owner Server: The server responsible for holding the room history, accepting new events, etc.
* Participant Server: Every other server. Note that a server may inherit this role even if not
  (currently) participating in the room.

**TODO**: Merge/add definitions from framework to here, such as "homeserver", "user", etc.

# Identifiers

**TODO**: Expand upon this section.

A room ID has the format `!localpart:domain`, where the localpart is an opaque string and the domain
provides global uniqueness. The domain does not indicate that the room exists on that server, just
that it was originally created there.

A user ID has the format `@localpart:domain`, where the localpart is again an opaque string and
the domain is where the user was created (the server owns the user account).

# Room Architecture

As mentioned, rooms over Linearized Matrix have a concept of an "owning server". Typically the
room owner will be the server which created the room, however ownership can shift as needed. The
room owner is responsible for applying the room version semantics/access controls and distributing
the changes to other applicable servers (called participant servers).

At an implementation level, it should be possible for an owning server to use a DAG if it so
wishes, however for the protocol considerations a room has a single flat array to store state
changes and room events.

Room state is the same as non-Linearized Matrix: represented by an event type and state key in
tuple form. "Current state" is simply the most recent instance of each event type and state key
pair in the array.

To send an event into the room, each "participant server" (non-owner) asks the owner to send it
to the room. The owner adds the event to the room's array, after simple validation, and sends it
out to all participating servers (including the original sender, for simplicity of implementation).
If the owner would like to send an event, it simply adds the event to the array (assuming such an
action is valid) and broadcasts it.

Each room additionally records which Matrix room version it is using for access control behaviours,
such as Authorization Rules {{MxV10AuthRules}}. This is required for when rooms gain a DAG-compatible
server in them. Note that this document introduces new semantics for a room version to be built
around, which would become the first elligible room version for a room using Linearized Matrix.

# Event Signing

Events are signed by the participant/original server to ensure the owning server is not spoofing
events on behalf of another server. The exact details for how a server's signing keys are shared
to other servers is left as a transport consideration, however signing keys are currently expected
to be ed25519 keys.

In the existing Matrix Federation APIs, a PDU {{MxV10PDUFormat}} contains an event and has several
DAG-specific fields to it. When using the Linearized Matrix API, we introduce a concept of a *Linear
PDU* which looks similar to a regular room event, but has all non-essential fields removed.

~~~ jsonc
{
  "room_id": "!room:example.org", // the room ID the event is sent within
  "type": "org.example.event_type", // the implied (or explicit) event type
  "state_key": "", // for state events, even if an empty string
  "sender": "@user:example.org", // the user ID of the sender
  "origin_server_ts": 123456789, // milliseconds since epoch
  "authorized_sending_server": "owner.example.org", // the domain of the room owner
  "content": {
    // the normal event content
  },
  "hashes": {
    "sha256": "<content hash, just like in Matrix today>"
  }
}
~~~

{{MxContentHashCalculation}}

The Linear PDU is then redacted {{MxRedaction}}, canonicalized {{MxCanonicalJSON}}, and signed
{{MxSigning}}. The signature is supplied to the owner server alongside the event itself for sending
to the room.

# Membership API

After a room is created (by an imagined `/createRoom` API, for example), it will exist on a single
server: the owner's. This is not particularly helpful if the goal is to talk to other people, so a
way to involve others in the conversation is needed.

Matrix currently has membership states for join, leave, invite, kick, ban, and knock (request invite).
These states have their own set of rules governed by the room version to prevent cases of, for example,
ban evasion.

**TODO**: Describe those membership transitions. Currently specified in the Client-Server API
https://spec.matrix.org/v1.6/client-server-api/#room-membership (we should move that).

A transport layer would describe a formal request/response structure for the membership APIs. Those
requests should be able to be rejected by the owner server prior to the membership transition happening
in the room, as the owner server may wish to apply additional checks for anti-abuse or similar.

Additionally, for invites specifically, the owner server MUST proxy an invite to the targeted
participant server before responding to the original invite request, if it has not already rejected
the request itself. This is to ensure the participant server has an opportunity to decline the
invite request for its own reasons, such as its own anti-abuse measures.

The owner server broadcasts successful membership changes as `m.room.member` events to all participant
servers in the room, including the sending server.

A server is considered to be "in the room" if it has at least one user with `join` membership state.

# State Events API

Matrix, and therefore Linearized Matrix, tracks changes to the room as *state events*. State events
have an event type and state key to differentiate them from room (or non-state) events. While history
for state changes is stored in the room, only the most recent change for an event type and state key
pair is considered "current state". For example, the current room name is the most recent `m.room.name`
state event.

As already mentioned in this document, a transport layer would be responsible for the request/response
structure for this API, however a need would be present to send (arbitrary) state events, read those
state events back, and read the whole of current state (including membership).

# Room Events API

Room events include messages and redactions, as well as messaging features like reactions, edits, etc.
These may be encrypted in supported rooms (ones which specify an encryption algorithm in their room state),
and in their unencrypted form will use the Matrix concept of Extensible Events.

**TODO**: Update the message format I-D for MSC1767 extensible events and link it here.
https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/1767-extensible-events.md

A transport layer would specify request/response structures for sending, receiving, reading, and
discovering nearby events (for scrollback purposes).

# Room Transfers

The current room owner would be stored as a state event within the room, defaulting to the room creator.
To transfer ownership, the current owner chooses a participant server and requests that it accept the
ownership role. If the participant server agrees to take ownership, it would create and sign a new room
ownership state event. The current owner then signs the ownership state event itself and sends it to all
participating servers (including the new owner), just as it would for any other event. All requests from
that point forward now go to the new owner, and the old owner becomes a regular participating server.

# Other APIs

**TODO**: Expand upon this section.

A transport layer would specify request/response structures for:

* Media/attachment distribution
* APIs to support end-to-end encryption
* Ephemeral data such as receipts, typing notifications, and presence
* Resolving an identifer to a room ID
* User profiles (display names and avatars)
* Other APIs as required to support interoperable messaging

# Matrix Room Version

The first room version which supports Linearized Matrix will base its requirements on Matrix's existing
Room Version 10 definition {{MxRoomVersion10}}. Changes will be made to support the following features:

* A description of the authorization rules when not using a DAG.
* The DAG-compatible signing structure for events.
* The use of Matrix's Extensible Events content format.

**TODO**: Expand upon this section with formal details of what the above looks like for a room version.

# DAG-Compatible Event Structure

Linearized Matrix is simply a simpler API for accessing a room on Matrix, which means servers which support
a full-blown DAG can still join and participate in the room. With DAG-compatible servers in the room, the
DAG-compatible servers talk to each other directly as they do with the current Matrix APIs, only involving
the room owner for state changes (like membership).

Normally, events are checked for signatures from the "origin" server implied by the `sender` on an event.
Events sent with the Linearized Matrix API are already signed by the participant server to ensure the owner
server isn't spoofing them, however an owner server might not always be DAG-compatible itself. To remedy this,
owner servers can delegate their DAG involvement to a DAG-compatible server in the room.

Delegating to a DAG-compatible server means creating a *Delegated Linear PDU* from a *Linear PDU*. The owner
moves the `authorized_sending_server` value (which should be itself) to `original_authorized_sending_server`
then populates `authorized_sending_server` with the domain name for the DAG-compatible server it is using.
The owner server then signs the Delegated Linear PDU and sends it to the DAG-compatible server, which then
appends all the DAG-specific fields and signs the resulting PDU itself before sending it to all the other
DAG-compatible servers in the room.

Note that while a Delegated Linear PDU modifies the structure that was signed as a Linear PDU, it is easily
possible to reconstruct a Linear PDU from a Delegated Linear PDU. Similarly, a DAG-ready PDU can be redacted
down to a Delegated Linear PDU with ease.

A complete DAG-ready PDU would look like:

~~~ jsonc
{
  "room_id": "!room:example.org", // the room ID the event is sent within
  "type": "org.example.event_type", // the implied (or explicit) event type
  "state_key": "", // for state events, even if an empty string
  "sender": "@user:example.org", // the user ID of the sender
  "origin_server_ts": 123456789,
  "original_authorized_sending_server": "owner.example.org", // the domain of the room owner
  "authorized_sending_server": "dag.example.org", // DAG-capable server; see bridging considerations for selection approach
  "content": {
    // the normal event content
  },
  "hashes": {
    "sha256": "<content hash, just like in Matrix today>"
  },
  // other event format stuff:
  "auth_events": ["$event1", "$event2", "$etc"],
  "depth": 42,
  "prev_events": ["$event3", "$event4", "$etc2"],
  "signatures": {
    "dag.example.org": {
      "ed25519:abc": "<signature for PDU>"
    },
    "owner.example.org": {
      "ed25519:def": "<signature for Delegated Linear PDU>"
    },
    "example.org": {
      "ed25519:ghi": "<signature for non-delegated Linear PDU>"
    }
  }
}
~~~

When validating the signatures {{MxSignatureValidation}} on this PDU, DAG-capable servers would apply the
following algorithm. If at any point the check fails, the algorithm bails.

1. If an `original_authorized_sending_server` is present, construct the implied Linear PDU from the PDU and
   validate the signature for the server implied by the `sender`. Additionally, redact the PDU down to a
   Delegated Linear PDU and validate the signature for the `authorized_sending_server` value.
2. If an `original_authorized_sending_server` is NOT present, redact the PDU down to a Linear PDU and validate
   the signature for the `authorized_sending_server` value.
3. Without considering the signatures from the domains in previous steps, verify the signatures per normal.
   Note that the step where the signature for the "origin server" (defined as the one implied by the PDU's
   `sender`) is implicitly checked as part of step 1 and 2, and not actually possible to verify in the
   traditional sense. That particular step in event validation is therefore skipped when step 1 or 2 is
   performed.

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
