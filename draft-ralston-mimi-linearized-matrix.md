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

# Federation architecture

~~~ aasvg
      {   Client A   }                                {   Client B   }
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
                                                      {   Client C   }
~~~



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

Room state is the same as non-Linearized Matrix: represented by an event type and state key tuple
which maps to a state event. "Current state" is simply the most recent instance of each event type
and state key pair in the array.

To send an event into the room, each "participant server" (non-owner) asks the owner to send it
to the room. The owner applies access controls to the event, following Matrix's existing access
controls (power levels, bans, server_acls etc.) and then adds the event to the room's array, and sends it
out to all participating servers (including the original sender, for simplicity of implementation).
If the owner would like to send an event, it simply adds the event to the array (assuming such an
action is valid) and broadcasts it. The owner server MUST follow the access control semantics defined
by the room's current state - it MUST NOT make up its own rules. For instance, the owning server
must only let Alice invite Bob to a room if Alice has permission to invite, and if Alice's server
sent the invite event.

Each room additionally records which Matrix room version it is using for access control behaviours,
such as Authorization Rules {{MxV10AuthRules}}. This is required for when rooms gain a DAG-compatible
server in them. Note that this document introduces new semantics requiring a new room version.

# Event Signing

Events are signed by the participant/original server to ensure the owning server is not spoofing
events on behalf of another server. The exact details for how a server's signing keys are shared
to other servers is left as a transport consideration, however signing keys are currently expected
to be Ed25519 keys.

In the existing Matrix Federation APIs, a PDU {{MxV10PDUFormat}} contains an event and has several
DAG-specific fields to it. When using the Linearized Matrix API, we introduce a concept of a *Linear
PDU* which looks similar to a regular room event, but has all non-essential fields removed.

~~~ jsonc
{
  // the room ID the event is sent within
  "room_id": "!room:example.org",
  // the implied (or explicit) event type
  "type": "org.example.event_type",
  // for state events, even if an empty string
  "state_key": "",
  // the user ID of the sender
  "sender": "@user:example.org",
  // milliseconds since epoch
  "origin_server_ts": 123456789,
  // the domain of the room owner
  "authorized_sending_server": "owner.example.org",
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

# Membership

After a room is created (by an imagined `/createRoom` API, for example), it will exist on a single
server: the owner's. This is not particularly helpful if the goal is to talk to other people, so a
way to involve others in the conversation is needed.

Matrix currently has membership states for join, leave, invite, kick, ban, and knock (request invite).
These states have their own set of rules governed by the room version to prevent cases of, for example,
ban evasion.

**TODO**: Describe those membership transitions. Currently specified in the Client-Server API
https://spec.matrix.org/v1.6/client-server-api/#room-membership (we should move that).

The owner server broadcasts successful membership changes as `m.room.member` events to all participant
servers in the room, including the sending server.

A server is considered to be "in the room" if it has at least one user with `join` membership state.

# State Events API

Matrix, and therefore Linearized Matrix, tracks changes to the room as *state events*. State events
have both an event type and state key to differentiate them from room (or non-state) events. While history
for state changes is stored in the room, only the most recent change for an event type and state key
pair is considered "current state". For example, the current room name is the most recent `m.room.name`
state event.

As mentioned above, a transport layer would be responsible for the request/response
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

**TODO**: What do you do if the owner server dies or partitions before transferring to a successor?

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

# Anti-Abuse and Anti-Spam

**TODO**: Expand upon this section.

In a Matrix room, state events get appended to the DAG/array to show intent. If a server wishes to decline
the request, such as in the case where the recipient server believes an invite is spammy, it can do so
by sending another event to the room. For example, an antispam system might issue redactions for messages
which look spammy on behalf of a room admin.

# DAG-Compatible Event Structure

Linearized Matrix is essentially an alternative API for accessing normal Matrix rooms over federation,
which means servers which support a full-blown DAG can still join and participate in the room.
This is critical in order to avoid breaking compatibility with today's fully-decentralized Matrix, and
provides a way to decentralize ownership of rooms even if large messaging providers are themselves
not able to implement full decentralization yet. {{?I-D.nottingham-avoiding-internet-centralization}}

With DAG-compatible servers in the room, the DAG-compatible servers talk to each other directly as they
do with the current Matrix APIs.  Any DAG-compatible server which can also speak Linearized Matrix
can connect to the owner server - effectively trunking Linearized Matrix into normal Matrix and tracking
its events into the DAG.  As long as servers speaking Linearized Matrix uphold the room's access controls,
then they appear as a single logical DAG-compatible server to normal Matrix, and will maintain consistency
with the rest of normal Matrix.

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
  // the room ID the event is sent within
  "room_id": "!room:example.org",
  // the implied (or explicit) event type
  "type": "org.example.event_type",
  // for state events, even if an empty string
  "state_key": "",
  // the user ID of the sender
  "sender": "@user:example.org",
  // milliseconds since epoch
  "origin_server_ts": 123456789,
  // the domain of the room owner
  "original_authorized_sending_server": "owner.example.org",
  // DAG-capable server
  "authorized_sending_server": "dag.example.org",
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

**TODO**: How does an owner server pick a DAG server to communicate with, and how does the owner receive events
from the DAG to send to participant servers? One option might be to have DAG-capable servers identify themselves
during joins with the owner server, then the current owner can transfer ownership to the DAG-capable server.
The DAG-capable owner would simply shuffle events around internally to feed both API surfaces, though this means
all DAG-capable servers need to implement both API surfaces.

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
