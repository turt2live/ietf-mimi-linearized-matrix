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
    date: 2023-04-12
    author:
       - fullname: Travis Ralston
         organization: The Matrix.org Foundation C.I.C.
         email: travisr@matrix.org
   DMLS:
     target: https://gitlab.matrix.org/matrix-org/mls-ts/-/blob/48efb972075233c3a0f3e3ca01c4d4f888342205/decentralised.org
     title: "Decentrlised MLS"
     date: 2023-05-29
     author:
       - fullname: Hubert Chathi
         organization: The Matrix.org Foundation C.I.C.

--- abstract

Matrix is an existing openly specified decentralized secure communications protocol
able to provide a framework for instant messaging interoperability. However, the
existing model can be complex to reason about for simple interoperability usecases.
With modifications to the room model, Matrix can support those simpler usecases more
easily.

This document explores "Linearized Matrix": the modified room model still backed by
Matrix.

--- middle

# Introduction

Alongside messaging, Matrix operates as an openly federated communications protocol for
VoIP, IoT, and more. The existing Matrix network uses fully decentralized access control
within rooms (conversations) and is highly extensible in its structure. These features
are not critically important to a strict focus on messaging interoperability, however.

This document describes "Linearized Matrix": a modified room model based upon Matrix's
existing room model. This document does *not* explore how to interconnect Linearized
Matrix with the existing Matrix room model - interested readers may wish to review
MSC3995 {{MSC3995}} within the Matrix Specification process.

# Conventions and Definitions

This document uses {{!I-D.ralston-mimi-terminology}} where possible.

This document additionally uses the following definitions:

* **Room**: Synonymous with "conversation" from I-D.ralston-mimi-terminology.
* **Room Member**: Synonymous with "conversation member" from I-D.ralston-mimi-terminology.
* **State Event**: Synonymous with "conversation property" from I-D.ralston-mimi-terminology.
  A state event is a subclass of an event.

Further terms are introduced in-context within this document.

**TODO**: We should move/copy those definitions up here anyways.

# Architecture

For a given conversation/room:

~~~ aasvg
       .------------.                                  .------------.
      |   Client A   |                                |   Client B   |
       '-----------+'                                  '-----------+'
        ^          |                                    ^          |
        |          |  Client-Server API                 |          |
        |          V                                    |          V
    +---+--------------+                            +---+--------------+
    |                  +----------( events )------->|                  |
    | Provider/Server  |                            | Provider/Server  |
    |        A         |<---------( events )--------+        B         |
    +-----+------------+     Server-Server API      +------------------+
          |     ^
          |     |                                   +------------------+
          |     +-----------------( events )--------+                  |
          |                                         | Provider/Server  |
          +-----------------------( events )------->|        C         |
                                                    +--------------+---+
                                                        ^          |
                                                        |          |
                                                        |          V
                                                       .+-----------.
                                                      |   Client C   |
                                                       '------------'
~~~

In this diagram, Server A is acting as a hub for the other two servers. Servers B and C do
not converse directly when sending events to the room: those events are instead sent to the
hub which then distributes them back out to all participating servers.

Clients are shown in the diagram here for demonstrative purposes only. No client-server API
is specified as part of Linearized Matrix, and the clients can be pre-existing or newly
created for messaging. The objects given to clients are implementation-dependent, though
for simplicity may be events.

This leads to two distinct roles:

* **Hub server**: the server responsible for holding conversation history on behalf of
  other servers in the room.

* **Participant server**: any non-hub server. This server is not required to persist
  conversation history as it can fetch it from the hub if needed.

**OPEN QUESTION**: Should we support having multiple hubs for increased trust between
participant and hub? (participant can pick the hub it wants to use rather than being
forced to use a single hub)

## Server names / domain names

Throughout this document servers are referred to as having a "domain name" or "server name".
A server name MUST be compliant with RFC 1123 (Section 2.1) {{!RFC1123}}.

**TODO**: Should we incorporate Matrix's IPv6 extension, or are we able to assume that
everyone will be using non-literal hostnames?

**TODO**: Do we really need to make this case sensitive? Matrix does, but is that correct?

## Rooms

A room is a conceptual place where users send and receive events. Events are sent to a room,
and all users which have sufficient access will receive that event.

Rooms have a single internal "Room ID" to identify them from another room:

~~~
!<opaque>:<domain>
~~~

For example, `!abc:example.org`.

The opaque portion of the room ID, called the localpart, must not be empty and must consist
entirely of the characters `[0-9a-zA-Z._~-]`.

The domain portion of a room ID does *NOT* indicate the room is "hosted" or served by that
domain. The domain is used as a namespace to prevent another server from maliciously taking
over a room. The server represented by that domain may no longer be participating in the room.

The total length (including the sigil and domain) of a room ID MUST NOT exceed 255 characters.

Room IDs are case sensitive.

## Users

As described by {{!I-D.ralston-mimi-terminology}}, a user is typically a human which operates
a client. In Linearized Matrix, all users have a User ID to distinguish them:

~~~
@<localpart>:<domain>
~~~

The localpart portion of the user ID is expected to be human-readable, MUST NOT be empty,
and MUST consist solely of `[0-9a-z._=-/]` characters. Note that user IDs *cannot* contain
uppercase letters in the localpart.

The domain portion indicates which server allocated the ID, or would allocate the resource
if the user doesn't exist yet. `@alice:first.example.org` is a different user on a different
server from `@alice:second.example.org`, for example.

The total length (including the sigil and domain) of a user ID MUST NOT exceed 255 characters.

User IDs are case sensitive.

**Note**: User IDs are sometimes informally referenced as "MXIDs", short for "Matrix User IDs".

**Author's note**: This draft assumes that an external system will resolve phone number to
user ID, somehow. Or that `@18005552222:example.org` will resolve to `+1 800 555 2222` on
a given server, or similar.

## Devices

Each user can have zero or more devices/active clients. These devices are intended to be members
of the MLS group and thus have their own key package material associated with them.

**TODO**: Do we need to define grammar and such for device IDs, or is that covered by MLS already?

## Events

All data exchanged over Linearized Matrix is expressed as an "event". Each client action
(such as sending a message) correlates with exactly one event. All events have a `type`
to distinguish them, and use reverse domain name notation to namespace custom events
(for example, `org.example.appname.eventname`). Event types specified by Linearized Matrix
itself use `m.` as their namespace.

When events are traversing a transport to another server they are often referred to as a
**Persistent Data Unit** or **PDU**.

An event has many other fields:

* `room_id` (string; required) - The room ID for where the event is being sent.

* `type` (string; required) - A UTF-8 {{!RFC3629}} string to distinguish different data types
  being carried by events. All event types use a reverse domain name notation to namespace
  themselves (for example, `org.example.appname.eventname`). Event types specified by
  Linearized Matrix itself use `m` as their namespace (for example, `m.room.member`).

* `state_key` (string; optional) - A UTF-8 {{!RFC3629}} string to further distinguish an event
  type from other related events. Only specified on State Events (discussed later). Can be
  empty.

* `sender` (string; required) - The user ID which is sending this event.

* `origin_server_ts` (integer; required) - The milliseconds since the unix epoch for when this
  event was created.

* `hub_server` (string; technically optional) - The domain name of the hub server which is
  sending this event to the remainder of the room. Note that all events created within Linearized
  Matrix will have this field set.

* `content` (object; required) - The event content. The schema of this is specific to the event
  type, and should be considered untrusted data until verified otherwise. Malicious servers and
  clients can, for example, exclude important fields, use invalid value types, or otherwise
  attempt to disrupt a client - receivers should treat the event with care while processing.

* `hashes` (object; required) - Keyed by hash algorithm, the *content hash* for the event.

* `signatures` (object; required) - Keyed first by domain name then by key ID, the signatures for
  the event.

* `auth_events` (array of strings; required) - The event IDs which prove the sender is able to
  send this event in the room. Which specific events are put here are defined by the *auth events
  selection* algorithm.

* `prev_events` (array of strings; required) - The event IDs which precede the event. Note that all
  events generated within Linearized Matrix will only ever have a single event ID here.

* `unsigned` (object; optional) - Additional metadata not covered by the signing algorithm.

Note that an event ID is not specified on the schema. Event IDs are calculated to ensure accuracy
and consistency between servers. To calculate an event ID, calculate the *reference hash* of the
event, encode it using *URL-safe Unpadded Base64*, and prefix it with the event ID sigil, `$`.

If both the sender and receiver are implementing the algorithms correctly, the event ID will be
the same. When different, the receiver will have issues accepting the event (none of the `auth_events`
will make sense, for example). Both sender and receiver should review their algorithm implementation
to verify everything is according to the specification in this case.

Events are treated as JSON {{!RFC8259}} within the protocol, but can be encoded and represented by
any binary-compatible format. Additional overhead may be introduced when converting between formats,
however.

An example may be:

~~~ json
{
  "room_id": "!abc:example.org",
  "type": "m.room.member",
  "state_key": "@alice:first.example.org",
  "sender": "@bob:second.example.org",
  "origin_server_ts": 1681340188825,
  "hub_server": "first.example.org",
  "content": {
    "membership": "invite"
  },
  "hashes": {
    "sha256": "<unpadded base64>"
  },
  "signatures": {
    "first.example.org": {
      "ed25519:1": "<unpadded base64 for signature covering whole event>"
    },
    "second.example.org": {
      "ed25519:1": "<unpadded base64 for signature covering LPDU>"
    }
  },
  "auth_events": ["$first", "$second"],
  "prev_events": ["$parent"],
  "unsigned": {
    "arbitrary": "fields"
  }
}
~~~

### Linearized PDU

The hub server is responsible for ensuring events are linearly added to the room from all participants,
which means participants cannot set fields such as `prev_events` on their events. Additionally,
participant servers are not expected to store past conversation history or even "current state" for
the room, further making participants unable to reliably populate `auth_events` and `prev_events`.

To avoid these problems, the participant server *does not* populate the following fields on events
they are sending to the hub:

* `auth_events` - the participant cannot reliably determine what allows it to send the event.
* `prev_events` - the participant cannot reliably know what event precedes theirs.
* `hashes` - the hashes cover the above two fields.

The participant server will receive an echo of the fully-formed event from the hub once appended.
To ensure authenticity, the participant server signs this "Linearized PDU" or "LPDU" using the
normal event *signing algorithm*.

**TODO**: While a signature is great, it doesn't cover the content. We need to fix `hashes` to
actually support an LPDU hash alongside a full-blown content hash.

### State events

State events track metadata for the room, such as name, topic, and members. State is keyed by a
tuple of `type` and `state_key`, noting that an empty string is a valid state key. State in the
room with the same key-tuple will be overwritten.

State events are otherwise processed like regular events in the room: they're appended to the
room history and can be referenced by that room history.

"Current state" is the state at the time being considered (which is often the implied `HEAD` of
the room). In Linearized Matrix, a simple approach to calculating current state is to iterate
over all events in order, overwriting the key-tuple for state events in an adjacent map. That
map becomes "current state" when the loop is finished.

### Event types

Linearized Matrix defines the following event types:

#### `m.room.create`

The very first event in the room. It MUST NOT have any `auth_events` or `prev_events`, and the
domain of the `sender` MUST be the same as the domain in the `room_id`. The `state_key` MUST
be an empty string.

The `content` for a create event MUST have at least a `room_version` field to denote what set
of algorithms the room is using. This document as a whole describes a single room version
identified as `I.1`.

**Implementation note**: Currently `I.1` is not a real thing. Use
`org.matrix.i-d.ralston-mimi-linearized-matrix.00` when testing against other Linearized Matrix
implementations. This room version may be updated later.

**TODO**: Describe room versions more?

#### `m.room.join_rules`

Defines whether users can join without an invite and other similar conditions. The `state_key`
MUST be an empty string.

The `content` for a join rules event MUST have at least a `join_rule` field to denote the
join policy for the room. Allowable values are:

* `public` - anyone can join without an invite.
* `knock` - users must receive an invite to join, and can request an invite (knock) too.
* `invite` - users must receive an invite to join.

**TODO**: Describe `restricted` (and `knock_restricted`) rooms?

#### `m.room.member`

Defines the membership for a user in the room. If the user does not have a membership event then
they are presumed to be in the `leave` state.

The `state_key` MUST be a non-empty string denotating the user ID the membership is affecting.

The `content` for a membership event MUST have at least a `membership` field to denote the
membership state for the user. Allowable values are:

* `leave` - not participating in the room. If the `state_key` and `sender` do not match, this was
  a kick rather than voluntary leave.
* `join` - participating in the room.
* `knock` - requesting an invite to the room.
* `invite` - invited to participate in the room.
* `ban` - implies kicked/not participating. Cannot be invited or join the room without being
  unbanned first (moderator sends a kick, essentially).

The *auth rules* define how these membership states interact and what legal transitions are possible.
For example, preventing users from unbanning themselves falls under the auth rules.

#### `m.room.power_levels`

Defines what given users can and can't do, as well as which event types they are able to send.
The enforcement of these power levels is determined by the *auth rules*.

The `state_key` MUST be an empty string.

The `content` for a power levels event SHOULD have at least the following:

* `ban` (integer) - the level required to ban a user. Defaults to `50` if unspecified.
* `kick` (integer) - the level required to kick a user. Defaults to `50` if unspecified.
* `invite` (integer) - the level required to invite a user. Defaults to `0` if unspecified.
* `redact` (integer) - the level required to redact an event sent by another user. Defaults
  to `50` if unspecified.
* `events` (map) - keyed by event type string, the level required to send that event type to
  the room. Defaults to an empty map if unspecified.
* `events_default` (integer) - the level required to send events in the room. Overridden by
  the `events` map. Defaults to `0` if unspecified.
* `state_default` (integer) - the level required to send state events in the room. Overridden
  by the `events` map. Defaults to `50` if unspecified.
* `users` (map) - keyed by user ID, the level of that user. Defaults to an empty map if
  unspecified.
* `users_default` (integer) - the level for users. Overridden by the `users` map. Defaults to
  `0` if unspecified.

**TODO**: Include notifications for at-room here too?

Note that if no power levels event is specified in the room then the room creator (`sender` of
the `m.room.create` state event) has a default power level of 100.

#### TODO: Other events

**TODO**: `m.room.name`, `m.room.topic`, `m.room.avatar`, `m.room.encryption`, `m.room.history_visibility`

**TODO**: Drop `m.room.encryption` and pack it into the create event instead?

# MLS Considerations

MIMI has a chartered requirement to use MLS for encryption, and MLS requires that all group
members (devices) know of all other devices. If we consider each Matrix room to have an MLS
group, we encounter scenarios where the room and group membership might diverge or otherwise
not be equivalent.

In a traditional Matrix room, membership is not managed at a per-device level but rather a
per-user level. Devices are authenticated to use the room by being attached to a user. This
model doesn't work in MLS, though.

A couple options present themselves:

1. Keep managing the room state at the server level, as is traditional for Matrix, and define
   a set of rules/methods for engaging devices/users in the room with the MLS group. Servers
   have an ability to instruct devices on how/when to add/remove MLS group members, but not
   an ability to handle the MLS Proposals and Commits directly.

2. Coordinate a room's state at the device level, leaving servers to figure out how to push
   events between servers (and by extension, other devices). Servers would not have knowledge
   or ability to reject proposals based on authorization beyond transport-level authenticity
   concerns.

At this stage of drafting in the document, it is not clear which would be preferred. Both are
explored.

## Decentralization and Append Only Operation

Although not explicitly covered by this document, there is interest in maintaining direct
interoperability with the existing non-linearized Matrix network as a whole. Decentralized
access to conversations in this way gives messaging providers a trust model which is less
dependent on a single other server (the room hub) being online and behaving correctly.

MLS however does not handle the required eventual consistency present in the existing Matrix
network. This is in large part due to it being impossible to "rewind" or go back to a previous
point in the encrypted history and insert/remove a series of events or messages.

To fix the rewind problem, Linearized Matrix is append only. Once an event is added to the
room's underlying linked list, it is there forever. The exact linearization algorithm is
out of scope for this document, though the important detail is a linearizing (DAG-capable)
server is *unable* to alter history through inserts or rejections.

For all other consistency problems imposed by decentralization, the Matrix team have been
working on Decentralized MLS {{DMLS}}. In DMLS, epoch counters are per-device rather than
per-group. This creates a graph of all commits with potential forks.

How forks are resolved in DMLS is also out of scope for this document. The current approach
is discussed and being experimented with from the early draft specification: {{DMLS}}.

**TODO**: DMLS might only be required if we use a client-side room model? Depends on how we
interoperate with non-linearized Matrix.

## Server-side Room Model

Discussed earlier in this section, in this model the server deals with handling the room
state on behalf of devices. This gives servers an ability to apply access control at a user
level and instruct other devices on when/how to add or remove devices from the MLS group.
The server does not have an ability to participate in the MLS group directly.

This is how traditional Matrix rooms work by handling state changes (user membership, etc)
in cleartext for everyone to see. A user's devices would be tracked and added/removed from
the MLS group as needed.

The exact rules for how a user's devices become engaged with the MLS group is not yet defined
in this model.

An advantage over this model compared to client-side is the server is able to reduce the
client's traffic, and likely keep things linear enough for MLS to function properly. This does
result in increased complexity for the server, however. No conflict resolution algorithm is
required for this case.

**TODO**: Is that true? We might need DMLS anyways to interop with non-linearized Matrix.

The remainder of this section covers how Linearized Matrix's server-side room model works.

### Event Signing & Authorization

There are a few aspects of an event which verify its authenticity and therefore whether it
can be accepted into the room. All of these checks work with the fully-formed PDU for an
event.

First, the event has a *content hash* which covers the unredacted content of the event. The
purpose of this hash is to ensure that the original contents are not modified, therefore if
the hash check fails then the event is redacted before continuing processing. This removes
any potentially malicious or malformed details from the event.

Second, the event has a *reference hash* which covers the redacted event. This hash serves
as the event's ID and thus any difference in calculation will result in an entirely different
event ID.

Third, the event must be signed by the domain implied by the `sender`. In Linearized Matrix,
this will usually be the LPDU signature discussed earlier in this document. This signature
covers the content hash of the event.

**TODO**: Except the LPDU signature doesn't cover the participant's content hash, because
the participant doesn't have a content hash at the moment. This needs to be fixed before
a 01 revision can be cut of this draft.

Finally, the event must be signed by the `hub_server` domain if present. This is to ensure
that the event has actually been processed by the hub and isn't falsely being advertised as
sent by a hub.

**TODO**: Does the hub's signature actually guard anything?

#### Checks performed upon receipt of a PDU/event

When a hub receives an LPDU from a participant it adds the missing fields to create a fully
formed PDU then sends that PDU back out to all participants, including the original sender.

When a server (hub or participant) receives a PDU, it:

1. Verifies the event is in a valid shape. This will mean ensuring the required schema is
   met and of the correct type (there is a string `type`, etc). Note that the event may
   have additional fields in various places, such as at the top level or within `content`:
   the receiver should ensure these additional fields do not cause the event to be invalid.
   If the event fails this validation, it is dropped.

2. Ensures the required signatures are present and valid. If the event fails this, it is
   dropped.

3. Ensures the event has a valid content hash. If the event's hash doesn't match, it is
   redacted before processing further. The server will ultimately persist the redacted
   copy.

4. Ensures the event passes the authorization rules for the state identified by the event's
   `auth_events`. If it fails, it is rejected.

5. Ensures the event passes the authorization rules for the state of the room immediately
   before where the event would be inserted. If it fails, it is rejected.

6. Ensures the event passes the authorization rules for the current state of the room (which
   may very well be the same as the step above). If it fails, it is soft-failed.

#### Rejection

Events which are rejected are not relayed to any local clients and are not appended to the
room in any way. Within Linearized Matrix, events which reference rejected events are
rejected themselves.

#### Soft failure

When an event is "soft-failed" it should not be relayed to any local clients nor be used
in `auth_events`. The event is otherwise handled as per usual.

#### Authorization rules

These are the rules which govern whether an event is accepted into the room, depending on
the state events surrounding that event. A given event is checked against multiple different
sets of state.

##### Auth events selection

The `auth_events` on an event MUST consist of the following state events, with the exception
of an `m.room.create` event which has no `auth_events`.

1. The `m.room.create` state event.
2. The current `m.room.power_levels` state event, if any.
3. The sender's current `m.room.member` state event, if any.
4. If the `type` is `m.room.member`:
   1. The target's (`state_key`) current `m.room.member` state event, if any.
   2. If `content.membership` is `join` or `invite`, the current `m.room.join_rules` state
      event, if any.

**TODO**: Talk about restricted room joins here?

##### Auth rules algorithm

With consideration for default/calculated power levels, the ordered rules which affect
authorization of a given event are:

**TODO**: should we reference `m.federate`?

1. Events must be signed by the server denoted by the `sender` field. Note that this may be
   an LPDU if the `hub_server` is specified and not the same server.

2. If `hub_server` is present, events must be signed by that server.

3. If `type` is `m.room.create`:

   1. If it has any `prev_events`, reject.
   2. If the domain of the `room_id` is not the same domain as the `sender`, reject.
   3. If `content.room_version` is not `I.1`, reject. **TODO**: Incorporate room versions properly.
   4. Otherwise, allow.

4. Considering the event's `auth_events`:

   1. If there are duplicate entries for a given `type` and `state_key` pair, reject.
   2. If there are entries whose `type` and `state_key` do not match those specified by the
      auth events selection algorithm, reject.
   3. If there are entries where the referenced event was rejected during receipt, reject.
   4. If there is no `m.room.create` event among the entries, reject.

5. If `type` is `m.room.member`:

   1. If there is no `state_key` property, or no `membership` in `content`, reject.

   2. If `membership` is `join`:

      1. If the previous event is an `m.room.create` event and the `state_key` is the
         creator, allow.
      2. If `sender` does not match `state_key`, reject.
      3. If the `sender` is banned, reject.
      4. If the `join_rule` for `m.room.join_rules` is `invite` or `knock`, then allow if
         the current membership state is `invite` or `join`.
      5. If the `join_rule` for `m.room.join_rules` is `public`, allow.
      6. Otherwise, reject.

   3. If `membership` is `invite`:

      1. If the `sender`'s current membership state is not `join`, reject.
      2. If the target user's (`state_key`) membership is `join` or `ban`, reject.
      3. If the `sender`'s power level is greater than or equal to the power level needed
         to send invites, allow.
      4. Otherwise, reject.

   4. If `membership` is `leave`:

      1. If the `sender` matches the `state_key`, allow if and only if that user's current
         membership state is `knock`, `join`, or `invite`.
      2. If the `sender`'s current membership state is not `join`, reject.
      3. If the target user's (`state_key`) current membership state is `ban`, and the
         `sender`'s power level is less than the power level needed to ban other users, reject.
      4. If the `sender`'s power level is greater than or equal to the power level needed to
         kick users, and the target user's (`state_key`) power level is less than the `sender`'s,
         allow.
      5. Otherwise, reject.

   5. If `membership` is `ban`:

      1. If the `sender`'s current membership state is not `join`, reject.
      2. If the `sender`'s power level is greater than or equal to the power level needed
         to ban users, and the target user's (`state_key`) power level is less than the
         `sender`'s power level, allow.
      3. Otherwise, reject.

   6. If `membership` is `knock`:

      1. If the `join_rule` for `m.room.join_rules` is anything other than `knock`, reject.
      2. If the `sender` does not match the `state_key`, reject.
      3. If the `sender`'s current membership state is not `ban` or `join`, allow.
      4. Otherwise, reject.

   7. Otherwise, the `membership` is unknown. Reject.

6. If the `sender`'s current membership state is not `join`, reject.

7. If the event `type`'s required power level is greater than the `sender`'s power level,
   reject.

8. If the event has a `state_key` which starts with an `@` and does not match the `sender`,
   reject.

9. If `type` is `m.room.power_levels`:

   1. If any of the fields `users_default`, `events_default`, `state_default`, `ban`, `redact`,
      `kick`, or `invite` in `content` are present and not an integer, reject.

   2. If `events` in `content` is present and not an object with values that are integers,
      reject.

   3. If the `users` in `content` is present and not an object with valid user IDs as keys and
      integers as values, reject.

   4. If there is no previous `m.room.power_levels` event in the room, allow.

   5. For the fields `users_default`, `events_default`, `state_default`, `ban`, `redact`, `kick`,
      and `invite`, check if they were added, changed, or removed. For each found alteration:

      1. If the current value is higher than the `sender`'s current power level, reject.
      2. If the new value is higher than the `sender`'s current power level, reject.

   6. For each entry being changed in or removed from `events`:

      1. If the current value is higher than the `sender`'s current power level, reject.

   7. For each entry being added to or changed in `events`:

      1. If the new value is greater than the `sender`'s current power level, reject.

   8. For each entry being changed in or removed from `users`, other than the `sender`'s own
      entry:

      1. If the current value is higher than the `sender`'s current power level, reject.

   9. For each entry being added to or changed in `users`:

      1. If the new value is greater than the `sender`'s current power level, reject.

   10. Otherwise, allow.

10. Otherwise, allow.


There are some consequences to these rules:

* Unless you are already a member of the room, the only permitted operations (aside from
  the initial create/join) are being able to join public rooms, accept invites to rooms,
  and reject invites to rooms.

* To unban another user, the sender must have a power level greater than or equal to both
  the kick and ban power levels, *and* greater than the target user's power level.

**TODO**: If we want to enforce a single hub in a room, we'd do so here with auth rules.

#### Signing

All servers, including hubs and participants, publish an ed25519 {{!RFC8032}} signing key
to be used by other servers when verifying signatures.

**TODO**: Verify RFC reference. We might be using a slightly different ed25519 key today?

##### Canonical JSON

When signing a JSON object, such as an event, it is important that the bytes be ordered in
the same way for everyone. Otherwise, the signatures will never match.

To canonicalize a JSON object, use {{!RFC8785}}.

**TODO**: Matrix currently doesn't use RFC8785, but it should (or similar).

##### Signing arbitrary objects

Though events receive a lot of signing, it is often necessary for a server to sign arbitary,
non-event, payloads as well. For example, in Matrix's existing HTTPS+JSON transport, requests
are signed to ensure they came from the source they claim to be.

To sign an object, the JSON is canonically encoded without the `signatures` or `unsigned`
fields. The bytes of the canonically encoded JSON are then signed using the ed25519 signing
key for the server. The resulting signature is then encoded using unpadded base64.

##### Signing events

Signing events is very similar to signing an arbitary object, however with a note that an event
is first redacted before signing. This ensures that later if the event were to be redacted in
the room that the signature check still passes.

Note that the content hash covers the event's contents in case of redaction.

###### Redacting an event

All fields at the top level except the following are stripped from the event:

* `type`
* `room_id`
* `sender`
* `state_key`
* `content`
* `origin_server_ts`
* `hashes`
* `signatures`
* `prev_events`
* `auth_events`
* `hub_server`

Additionally, some event types retain specific fields under the event's `content`. All other
fields are stripped.

* `m.room.create` retains all fields in `content`.
* `m.room.member` retains `membership`.
* `m.room.join_rules` retains `join_rule`.
* `m.room.power_levels` retains `ban`, `events`, `events_default`, `kick`, `redact`, `state_default`,
  `users`, `users_default`, and `invite`.
* `m.room.history_visibility` retains `history_visibility`.

##### Checking a signature

If the `signatures` field is missing, doesn't contain the entity that is expected to have done
the signing (a server name), doesn't have a known key ID, or is otherwise structurally invalid
then the signature check fails.

If decoding the base64 fails, the check fails.

If removing the `signatures` and `unsigned` properties, canonicalizing the JSON, and verifying
the signature fails, the check fails.

Otherwise, the check passes.

#### Hashes

An event is covered by two hashes: a content hash and a reference hash. The content hash covers the
unredacted event to ensure it was not modified in transit. The reference hash covers the essential
fields of the event, including content hashes, and serves as the event's ID.

##### Content hash calculation

1. Remove any existing `unsigned`, `signatures`, and `hashes` fields.
2. Encode the object using canonical JSON.
3. Hash the resulting bytes with SHA-256 {{!RFC6234}}.
4. Encode the hash using unpadded base64.

##### Reference hash

1. Redact the event.
2. Remove `signatures` and `unsigned` fields.
3. Encode the object using canonical JSON.
4. Hash the resulting bytes with SHA-256 {{!RFC6234}}.
5. Encode the hash using URL-safe unpadded base64.

#### Unpadded Base64

Throughout this document, "unpadded base64" is used to represent binary values as strings. Base64 is
as specified by {{!RFC4648}}, and *unpadded* base64 simply removes any `=` padding from the resulting
string.

Implementations SHOULD accept input with or without padding on base64 values.

Section 5 of {{!RFC4648}} describes *URL-safe* base64. The same changes are adopted here. Namely, the
62nd and 63rd characters are replaced with `-` and `_` respectively. The unpadded behaviour is as
described above.

## Client-side Room Model

In this model, a room's state is completely managed within the MLS group. This provides a key advantage
where servers become message-passing nodes (in essence), but increases implementation complexity on the
clients/devices.

Much of this model is based around the server-side model discussed above: event authorization rules,
redactions, etc still behave the same, but on the client-side instead. The server would likely be
responsible for ensuring incoming events are properly signed, but otherwise leave it up to clients to
accept or reject them into their internal linked list.

A potential consequence of this model is clients needing to implement a conflict resolution algorithm
despite having linear room history. This is due to clients receiving MLS messages out of guaranteed order.

**TODO**: This could be DMLS, state res, or both.

# Hub transfers

**TODO**: This section, if we want a single canonical hub in the room. Some expected problems in this
area are: who signs the transfer event? who *sends* the transfer event? how does a transfer start?

# Transport

**TODO**: This section, though this is likely to be a dedicated I-D.

Topics:
* Server discovery
* Publishing of signing keys
* Sending events between servers
* Media handling
* etc

Matrix currently uses an HTTPS+JSON transport for this.

# Security Considerations

**TODO**: Expand upon this section.

# IANA Considerations

The `m.*` namespace likely needs formal registration in some capacity.

--- back

# Acknowledgments
{:numbered="false"}

Thank you to the Matrix Spec Core Team (SCT), and in particular Richard van der Hoff, for
exploring how Matrix rooms could be represented as a linear structure, leading to this document.
