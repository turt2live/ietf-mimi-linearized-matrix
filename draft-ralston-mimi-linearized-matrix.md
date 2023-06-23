---
title: "Linearized Matrix"
abbrev: "Linearized Matrix"
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
  RFC6125:
  RFC4291:
  RFC4648:
  RFC1123:

informative:
  RFC6120:
  MSC3995:
    target: https://github.com/matrix-org/matrix-spec-proposals/pull/3995
    title: "MSC3995: [WIP] Linearized Matrix"
    date: 2023-04-12
    author:
       - fullname: Travis Ralston
         organization: The Matrix.org Foundation C.I.C.
         email: travisr@matrix.org
  MSC3820:
    target: https://github.com/matrix-org/matrix-spec-proposals/pull/3820
    title: "MSC3820: Room Version 11"
    date: 2023-06-08
    author:
       - fullname: Travis Ralston
         organization: The Matrix.org Foundation C.I.C.
         email: travisr@matrix.org
  DMLS: # TODO: Actually link to this somewhere in the doc.
    target: https://gitlab.matrix.org/matrix-org/mls-ts/-/blob/48efb972075233c3a0f3e3ca01c4d4f888342205/decentralised.org
    title: "Decentralised MLS"
    date: 2023-05-29
    author:
       - fullname: Hubert Chathi
         organization: The Matrix.org Foundation C.I.C.
  PerspectivesProject:
    target: https://web.archive.org/web/20170702024706/https://perspectives-project.org/
    title: "Perspectives Project"
    date: 2017-07-02

--- abstract

This document specifies Linearized Matrix for use in messaging interoperability.

--- middle

# Introduction

Alongside messaging, Matrix operates as an openly federated communications protocol for
VoIP, IoT, and more. The existing Matrix network uses fully decentralized access control
within rooms (conversations) and is highly extensible in its structure. These features
are not critically important to a strict focus on messaging interoperability, however.

This document specifies "Linearized Matrix": a modified room model based upon Matrix's
existing room model. This document does *not* explore how to interconnect Linearized
Matrix with the existing Matrix room model - interested readers may wish to review
{{MSC3995}} within the Matrix Specification process.

At a high level, a central server is designated as the "hub" server, responsible for
ensuring events in a given room are provided to all other participants equally. Servers
communicate with each other over HTTPS and JSON, using the specified API endpoints.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

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
   '---------+--'                                  '---------+--'
      ^      |                                        ^      |
      |      |  Client-Server API                     |      |
      |      V                                        |      V
+-----+------------+                            +-----+------------+
|                  +----------( events )------->|                  |
| Provider/Server  |                            | Provider/Server  |
|        A         |<---------( events )--------+        B         |
+-----+------------+     Server-Server API      +------------------+
      |     ^
      |     |                      +------------------+
      |     +----( events )--------+                  |
      |                            | Provider/Server  |
      +----------( events )------->|        C         |
                                   +------------+-----+
                                         ^      |
                                         |      |
                                         |      V
                                      .--+---------.
                                     |   Client C   |
                                      '------------'
~~~

In this diagram, Server A is acting as a hub for the other two servers. Servers B and C do
not converse directly when sending events to the room: those events are instead sent to the
hub which then distributes them back out to all participating servers.

Clients are shown in the diagram here for demonstrative purposes only. No Client-Server API
or other requirements of clients are specified in this document.

This leads to two distinct roles:

* **Hub server**: the server responsible for holding conversation history on behalf of
  other servers in the room.

* **Participant server**: any non-hub server. This server is not required to persist
  conversation history as it can fetch it from the hub if needed.

**OPEN QUESTION**: Should we support having multiple hubs for increased trust between
participant and hub? (participant can pick the hub it wants to use rather than being
forced to use a single hub)

## Server Names {#int-server-names}

Each server has a "domain name" or "server name" to uniquely identify it. This server name is
then used to namespace user IDs, room IDs/aliases, etc.

A server name MUST be compliant with {{Section 2.1 of RFC1123}} and, when an IPv6 address,
encoded per {{Section 2.2 of RFC4291}} surrounded by square brackets (`[]`). Improper server
names MUST be considered "uncontactable" by a server.

A server SHOULD NOT use a literal IPv4 or IPv6 address as a server name. Doing so reduces the
ability for the server to move to another internet address later, and IP addresses are generally
difficult to acquire certificates for (required in {{int-transport}}). Additionally, servers
SHOULD NOT use an explicit port in their server name for similar portability reasons.

The approximate ABNF {{!RFC5234}} grammar for a server name is:

~~~
server_name = hostname [ ":" port ]
port        = 1*5DIGIT
hostname    = IPv4address / "[" IPv6address "]" / dns-name
IPv4address = 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
IPv6address = 2*45IPv6char
IPv6char    = DIGIT / %x41-46 / %x61-66 / ":" / "."
                  ; 0-9, A-F, a-f, :, .
dns-name    = 1*255dns-char
dns-char    = DIGIT / ALPHA / "-" / "."
~~~

Server names MUST be treated as case sensitive (`eXaMpLe.OrG`, `example.org`, and `EXAMPLE.ORG`
are 3 different servers). Server names SHOULD be lower case (`example.org`) and SHOULD NOT exceed
230 characters for ease of use.

Examples:
* `example.org` (DNS host name)
* `example.org:5678` (DNS host name with explicit port)
* `127.0.0.1` (literal IPv4 address)
* `127.0.0.1:5678` (literal IPv4 address with explicit port)
* `[2001:DB8:0:0:8:800:200C:417A]` (literal IPv6 address)
* `[2001:DB8:0:0:8:800:200C:417A]:5678` (literal IPv6 address with explicit port)

## Rooms {#int-room-id}

Rooms hold the same definition under {{!I-D.ralston-mimi-terminology}}: a conceptual place
where users send and receive events. All users with sufficient access to the room receive
events sent to that room.

The different chat types are represented by rooms through state events ({{int-state-events}}), which
ultimately change how the different algorithms in the room version ({{int-room-versions}}) behave.

Rooms have a single internal "Room ID" to identify them from another room. The ABNF {{!RFC5234}}
grammar for a room ID is:

~~~
room_id = "!" room_id_localpart ":" server_name
room_id_localpart = 1*opaque
opaque = DIGIT / ALPHA / "-" / "." / "~" / "_"
~~~

`server_name` is inherited from {{int-server-names}}.

`room_id` MUST NOT exceed 255 characters and MUST be treated as case sensitive.

Example: `!abc:example.org`.

The `server_name` for a room ID does *NOT* indicate the room is "hosted" or served by that
domain. The domain is used as a namespace to prevent another server from maliciously taking
over a room. The server represented by that domain may no longer be participating in the room.

The entire room ID after the `!` sigil MUST be treated as opaque. No part of the room ID should
be parsed, and cannot be assumed to be human-readable.

### Room Versions {#int-room-versions}

**TODO**: We should consider naming this something else.

A room version is a set of algorithms which define how the room operates, identified by a single
string. Room versions are immutable once specified, as otherwise a change in algorithms could
cause a split-brain between participating servers.

Room versions prefixed with `I.` MUST only be used within the IETF specification process.
Room versions consisting solely of `0-9` and `.` MUST only be used by the Matrix protocol.

There is no implicit ordering or hierarchy to room versions. Although there is a recommended
default room version, some rooms might benefit from features of a different room version.

A room version has the following algorithms defined:

* Event authorization - Rules which govern when events are accepted, rejected, or soft-failed
  by a server.
* Redaction - Description of which fields to keep on an event during redaction. Redaction is
  used by the signing and hash algorithms, meaning they need to be consistent across implementations.
* Event format - Which fields are expected to be present on an event, and the schema for each.
* Canonical JSON - Specific details about how to canonicalize an event as JSON. This is used
  by the signing algorithm and must be consistent between implementations.
* Hub selection - Rules around picking the hub server and transferring to a new hub.
* Identifier grammar - All identifiers (room IDs, user IDs, event IDs, etc) can change grammar
  within a room version. As such, they SHOULD generally be treated as opaque as possible over a
  transport.

A server is capable of supporting multiple room versions at a time. The transport API decouples
specific details regarding room versions from the wire formats. For example, events are treated
as JSON blobs in this document's Server-Server API ({{int-transport}}).

Room versions are normally specified using a dedicated document. An example of this can be found
in the existing Matrix Spec Change process as {{MSC3820}}.

Each room version has a "stable" or "unstable" designation. Stable room versions SHOULD be used
in production by messaging providers. Unstable room versions might contain bugs or are not yet
fully specified and SHOULD NOT be used in production by messaging providers.

**TODO**: Matrix considers a version as stable once accepted through FCP. When would be the
process equivalent for the IETF?

The ABNF {{!RFC5234}} grammar for a room version is:

~~~
room_version = 1*128room_version_char
room_version_char = DIGIT
                  / %x61-7A         ; a-z
                  / "-" / "."
~~~

Examples:

* `1`
* `I.1`
* `org.example.my-room-version`

Room versions not formally specified SHOULD be prefixed using reverse domain name notation,
creating a sort of namespace. `org.example.my-room-version` is an example of this.

## Users {#int-user-id}

As described by {{!I-D.ralston-mimi-terminology}}, a user is typically a human which operates
a client. Each user has a distinct user ID.

The ABNF {{!RFC5234}} grammar for a user ID is:

~~~
user_id = "@" user_id_localpart ":" server_name
user_id_localpart = 1*user_id_char
user_id_char = DIGIT
             / %x61-7A                   ; a-z
             / "-" / "." / "="
             / "_" / "/" / "+"
~~~

`server_name` is inherited from {{int-server-names}}.

`user_id` MUST NOT exceed 255 characters and MUST be treated as case sensitive.

Examples:

* `@alice:example.org`
* `@watch/for/slashes:example.org`

`user_id_localpart` SHOULD be human-readable and notably MUST NOT contain uppercase letters.

`server_name` denotes the domain name ({{int-server-names}}) which allocated the ID, or would allocate
the ID if the user doesn't exist yet.

Identity systems and messaging providers SHOULD NOT use a phone number in a localpart, as the
localpart for a user ID is unchangeable. In these cases, a GUID (scoped to the allocating server)
is recommended so the associated human can change their phone number without losing chats.

This document does not define how a user ID is acquired. It is expected that an identity specification
under MIMI will handle resolving email addresses, phone numbers, names, and other common queries
to user IDs.

User IDs are sometimes informally referenced as "MXIDs", short for "Matrix User IDs".

## Devices

Each user can have zero or more devices/active clients. These devices are intended to be members
of the MLS group and thus have their own key package material associated with them.

**TODO**: Do we need to define grammar and such for device IDs, or is that covered by MLS already?

## Events {#int-pdu}

All data exchanged over Linearized Matrix is expressed as an "event". Each client action
(such as sending a message) correlates with exactly one event. All events have a `type`
to distinguish them, and use reverse domain name notation to namespace custom events
(for example, `org.example.appname.eventname`).

Event types using `m.` as a prefix MUST only be used by the protocol.

When events are traversing a transport to another server they are referred to as a
**Persistent Data Unit** or **PDU**. Structurally, an event and PDU are the same.

An event has the following minimum fields:

* `room_id` (string; required) - The room ID for where the event is being sent. This MUST be
  a valid room ID ({{int-room-id}}).

* `type` (string; required) - A UTF-8 {{!RFC3629}} string to distinguish different data types
  being carried by events. Event types are case sensitive. This MUST NOT exceed 255 characters.

* `state_key` (string; optional) - A UTF-8 {{!RFC3629}} string to further distinguish an event
  type from other related events. Only specified on State Events ({{int-state-events}}). Can be
  empty. This MUST NOT exceed 255 characters.

* `sender` (string; required) - The user ID which is sending this event. This MUST be a valid
  user ID ({{int-user-id}}).

* `origin_server_ts` (integer; required) - The milliseconds since the unix epoch for when this
  event was created.

* `hub_server` (string; technically optional) - The domain name of the hub server which is
  sending this event to the remainder of the room. All events created within Linearized Matrix
  MUST have this field set, however events created externally MUST NOT set this field. This
  MUST be a valid server name ({{int-server-names}}).

* `content` (object; required) - The event content. The specific schema depends on the event
  type. Clients and servers processing an event MUST NOT assume the `content` is safe or
  accurately represented. Malicious clients and servers are able to send payloads which don't
  comply with a given schema, which may cause unexpected behaviour on the receiving side.
  For example, a field marked as "required" might be missing.

* `hashes` (object; required) - The *content hashes* for the event. The `lpdu` key within this
  object is an object itself, keyed by hash algorithm with value being the encoded hash. Similarly,
  outside of `lpdu`, `hashes` is keyed by hash algorithm with value being the encoded hash.
  Events created within Linearized Matrix MUST specify an LPDU hash, however events created
  externally MUST NOT set such a hash.

* `signatures` (object; required) - Keyed first by domain name then by key ID, the signatures for
  the event.

* `auth_events` (array of strings; required) - The event IDs which prove the sender is able to
  send this event in the room. Which specific events are put here are defined by the auth events
  selection algorithm ({{int-auth-selection}}).

* `prev_events` (array of strings; required) - The event IDs which precede the event. Events
  created within Linearized Matrix MUST only ever have a single event ID here, however events
  created externally MAY have one or more referenced event IDs.

* `unsigned` (object; optional) - Additional metadata not covered by the signing algorithm. Like
  `content`, a receiver MUST NOT trust the values to match any particular schema.

Note that an event ID is not specified on the schema. Event IDs are calculated to ensure accuracy
and consistency between servers. To determine the ID for an event, calculate the reference hash
({{int-reference-hashes}}) then encode it using URL-safe Unpadded Base64 ({{int-unpadded-base64}})
and prefix that with the event ID sigil, `$`. For example, `$nKHVqt3iyLA_HEE8lT1yUaaVjjBRR-fAqpN4t7opadc`.

The ABNF {{!RFC5234}} for an event ID is:

~~~
event_id = "$" reference_hash
reference_hash = 1*urlsafe_unpadded_base64_char
urlsafe_unpadded_base64_char = ALPHA / DIGIT / "-" / "_"
~~~

If both the sender and receiver are implementing the algorithms correctly, the event ID will be
the same. When different, the receiver will have issues accepting the event (none of the `auth_events`
will make sense, for example). The sender and receiver will need to review that their implementation
matches the specification in this case.

Events are treated as JSON {{!RFC8259}} within the protocol, but can be encoded and represented by
any binary-compatible format. Additional overhead may be introduced when converting between formats,
however.

An example event is:

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
    "lpdu": {
      "sha256": "<unpadded base64>"
    },
    "sha256": "<unpadded base64>"
  },
  "signatures": {
    "first.example.org": {
      "ed25519:1": "<unpadded base64 signature covering whole event>"
    },
    "second.example.org": {
      "ed25519:1": "<unpadded base64 signature covering LPDU>"
    }
  },
  "auth_events": ["$first", "$second"],
  "prev_events": ["$parent"],
  "unsigned": {
    "arbitrary": "fields"
  }
}
~~~

An event/PDU MUST NOT exceed 65536 bytes when formatted using Canonical JSON ({{int-canonical-json}}).
Note that this includes all `signatures` on the event.

Fields have no size limit unless specified above, other than the maximum 65536 bytes for the whole
event.

### Linearized PDU {#int-lpdu}

The hub server is responsible for ensuring events are linearly added to the room from all participants,
which means participants cannot set fields such as `prev_events` on their events. Additionally,
participant servers are not expected to store past conversation history or even "current state" for
the room, further making participants unable to reliably populate `auth_events` and `prev_events`.

To avoid these problems, the participant server MUST NOT populate the following fields on events
they are sending to the hub:

* `auth_events` - the participant cannot reliably determine what allows it to send the event.
* `prev_events` - the participant cannot reliably know what event precedes theirs.
* `hashes` (except `hashes.lpdu`) - top-level hashes cover the above two fields.

The participant server MUST populate the `hashes.lpdu` object, covering a content hash
({{int-content-hashes}}) of the partial event, giving authenticity to the sender's contents. The
participant server additionally signs this partial event before sending it to the hub.

The participant server will receive an echo of the fully-formed event from the hub once appended
to the room.

### State Events {#int-state-events}

State events track metadata for the room, such as name, topic, and members. State is keyed by a
tuple of `type` and `state_key`, noting that an empty string is a valid state key. State in the
room with the same key-tuple will be overwritten as "current state".

State events are otherwise processed like regular events in the room: they're appended to the
room history and can be referenced by that room history.

"Current state" is the state at the time being considered (which is often the implied `HEAD` of
the room). In Linearized Matrix, a simple approach to calculating current state is to iterate
over all events in order, overwriting the key-tuple for state events in an adjacent map. That
map becomes "current state" when the loop is finished.

### Event Types

Linearized Matrix defines the following event types. The section headers are the event `type`.

#### `m.room.create`

The very first event in the room. It MUST NOT have any `auth_events` or `prev_events`, and the
domain of the `sender` MUST be the same as the domain in the `room_id`. The `state_key` MUST
be an empty string.

The `content` for a create event MUST have at least a `room_version` field to denote what set
of algorithms the room is using.

These conditions are checked as part of the event authorization rules ({{int-auth-rules}}).

#### `m.room.join_rules`

Defines whether users can join without an invite and other similar conditions. The `state_key`
MUST be an empty string. Any other state key, including lack thereof, serve no meaning and
are treated as though they were a custom event.

The `content` for a join rules event MUST have at least a `join_rule` field to denote the
join policy for the room. Allowable values are:

* `public` - anyone can join without an invite.
* `knock` - users must receive an invite to join, and can request an invite (knock) too.
* `invite` - users must receive an invite to join.

**TODO**: Describe `restricted` (and `knock_restricted`) rooms?

**TODO**: What's the default?

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

These conditions are checked as part of the event authorization rules ({{int-auth-rules}}),
as are the rules for moving between membership states.

#### `m.room.power_levels`

Defines what given users can and can't do, as well as which event types they are able to send.
The enforcement of these power levels is determined by the event authorization rules ({{int-auth-rules}}).

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

These conditions are checked as part of the event authorization rules ({{int-auth-rules}}).

##### Calculating Power Levels {#int-calc-power-levels}

All power levels are calculated with reference to the `content` of an `m.room.power_levels`
state event.

To calculate a user's current power level:

1. If `users` is present, use the power level for the user ID, if present.
2. If `users` is not present, or the user ID is not present in `users`, use `users_default`.
3. If `users_default` is not present, use `0`.

To calculate the required power level to do an action:

1. If the action (`kick`, `ban`, `invite`, or `redact`) is present, use that power level.
2. If not present, use the default for the action (`50` for `kick`, `ban`, and `redact`, `0`
   for `invite`).

To calculate the required power level to send an event:

1. If `events` is present, use the power level for the event `type`, if present.
2. If `events` is not present, or the event `type` is not present in `events`:
   1. If `state_key` is present (including empty), use `state_default`.
      1. If `state_default` is not specified, use `50`.
   2. If `state_key` is not present, use `events_default`.
      1. If `events_default` is not specified, use `0`.

#### `m.room.history_visibility`

**TODO**: Describe.

##### Calculating Event Visibility {#int-calc-event-visibility}

**TODO**: Describe. (when can a server see an event?)

#### TODO: Other events

**TODO**: `m.room.name`, `m.room.topic`, `m.room.avatar`, `m.room.encryption`

**TODO**: Drop `m.room.encryption` and pack it into the create event instead?

# Initial Room Version

Room versions are described by {{int-room-versions}}.

As a whole, this document describes the `I.1` room version. Future room versions can build
upon this version's principles (or entirely replace them) through dedicated documents.

Servers MUST implement support for `I.1`, and SHOULD implement other specified room versions
as needed. Servers SHOULD use `I.1` when creating new rooms. `I.1` shall be considered "stable".

**Implementation note**: Currently `I.1` is not a real thing. Use
`org.matrix.i-d.ralston-mimi-linearized-matrix.02` when testing against other Linearized Matrix
implementations. This string may be updated later to account for breaking changes.

**Implementation note**: `org.matrix.i-d.ralston-mimi-linearized-matrix.00` also exists in the
wild, defining a set of algorithms which exist in a prior version of this document (00 and 01).

**TODO**: Remove implementation notes.

The hub server MUST enforce the room version's algorithms upon the room. Participant servers
SHOULD enforce the room version's algorithm, but can opt to believe the hub server if they
wish.

# MLS Considerations

MIMI has a chartered requirement to use Messaging Layer Security (MLS) {{!I-D.ietf-mls-protocol}}
{{!I-D.ietf-mls-architecture}} for encryption, and MLS requires that all group members (devices)
know of all other devices.

Each room has a single MLS Group associated with it, starting with the `m.room.create` event.

**TODO**: Details on how key material is stored/shared within the room.

**TODO**: What does `m.room.encrypted` (user message) look like here?

# Event Signing & Authorization

An event has several authenticity properties:

* Content hashes ({{int-content-hashes}}) to cover the LPDU ({{int-lpdu}}) and event ({{int-pdu}})
  contents.
* Reference hashes ({{int-reference-hashes}}) which double as the event ID, covering the
  redacted event.
* Signatures from the direct senders (server name of the `sender` and the `hub_server` if
  present), ensuring the entities did actually produce that event.

**TODO**: Does the hub's signature actually guard anything?

These properties are validated throughout this document. Each property has different behaviour
when violated. For example, a difference in content hash ultimately causes the event to be
stored as a redacted copy.

## Receiving Events/PDUs {#int-receiving-events}

When a hub receives an LPDU from a participant it MUST add the missing fields to create a fully
formed PDU then MUST send that PDU back out to all participants, including the original sender.

A server is considered to have "received" an event when it sees it for the first time. This
might be because the server specifically reached out to fetch that specific event, or because
the server was pushed that event through normal operation.

When a server (hub or participant) receives an event, it MUST:

1. Verify the event is in a valid shape ({{int-pdu}}). In practice, this means ensuring the
   overall schema for an event is applied, without considering specific schemas for `content`.
   For example, ensuring a `type` is present, a string, and less than 255 characters. If an
   event fails to meet this requirement, it is dropped/ignored.

2. Ensure the required signatures are present and that they are valid ({{int-checking-signatures}}).
   If the event has a `hub_server` field, the event MUST be signed by that server. The event
   MUST also be signed by the server implied by the `sender`, noting that this will be an LPDU
   if `hub_server` is present. All other signatures MUST NOT be considered for signature
   validation, regardless of their individual validity. If the event fails to meet this
   requirement, it is dropped/ignored.

3. Ensure the event has a valid content hashes ({{int-content-hashes}}). If the event has a
   `hub_server` field, it MUST have a content hash which covers the LPDU. If either the LPDU
   or PDU content hash doesn't match what the receiving server calculations, the event is
   redacted before further processing. The server will ultimately persist the redacted copy.

Additionally, a hub server MUST complete the following checks. Participant servers SHOULD
also complete the checks to validate the hub's behaviour.

4. Ensure the event is not referencing rejected ({{int-rejection}}) events. If it is, it is
   rejected itself.

5. Ensure the event passes the authorization rules ({{int-auth-rules}}) for the state identified
   by the event's `auth_events`. If it fails, it is rejected ({{int-rejection}}).

6. Ensures the event passes the authorization rules ({{int-auth-rules}}) for the state of the
   room immediately before where the event would be inserted. If it fails, it is rejected
   ({{int-rejection}}).

   **TODO**: Clarify that this step only applies if you're on the DAG side. On LM, this is
   the same as Step 6. We may need to adjust the rejection/soft-fail logic.

7. Ensures the event passes the authorization rules ({{int-auth-rules}}) for the current
   state of the room (which may very well be the same as the step above). If it fails, it
   is soft-failed ({{int-soft-failure}}).

## Rejection {#int-rejection}

Events which are rejected are not relayed to any local clients and are not appended to the
room in any way. Events which reference rejected events through `prev_events` or `auth_events`
are rejected themselves.

Servers which utilize persistence (hub servers) SHOULD persist rejections to make this check
faster.

## Soft Failure {#int-soft-failure}

When an event is "soft-failed" it should not be relayed to any local clients nor be used
in `auth_events`. The event is otherwise handled as per usual.

**TODO**: With a linearized DAG, do we have a choice to not use the event in auth_events?

## Authorization Rules {#int-auth-rules}

These are the rules which govern whether an event is accepted into the room, depending on
the state events surrounding that event. A given event is checked against multiple different
sets of state.

### Auth Events Selection {#int-auth-selection}

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

### Auth Rules Algorithm

With consideration for default/calculated power levels ({{int-calc-power-levels}}), the
ordered rules which affect authorization of a given event are as follows.

See {{int-rejection}} for a description of "reject".

**TODO**: should we reference `m.federate`?

1. Events must be signed ({{int-checking-signatures}}) by the server denoted by the `sender`
   field. Note that this may be an LPDU if the `hub_server` is specified and not the same server.

2. If `hub_server` is present, events must be signed ({{int-checking-signatures}}) by that server.

3. If `type` is `m.room.create`:

   1. If it has any `prev_events`, reject.
   2. If the domain of the `room_id` is not the same domain as the `sender`, reject.
   3. If `content.room_version` is not `I.1`, reject.
   4. Otherwise, allow.

4. Considering the event's `auth_events`:

   1. If there are duplicate entries for a given `type` and `state_key` pair, reject.
   2. If there are entries whose `type` and `state_key` do not match those specified by the
      auth events selection algorithm ({{int-auth-selection}}), reject.
   3. If there are entries where the referenced event was rejected during receipt ({{int-rejection}}),
      reject.
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

# Signing {#int-signing}

All servers, including hubs and participants, publish an ed25519 {{!RFC8032}} signing key
to be used by other servers when verifying signatures.

**TODO**: Verify RFC reference. We might be using a slightly different ed25519 key today?
See https://hdevalence.ca/blog/2020-10-04-its-25519am

Each key ID consists of an algorithm name and version. Signing keys MUST use an algorithm
of `ed25519` (and therefore MUST be an ed25519 key). The key version MUST be valid under
the following ABNF {{!RFC5234}}:

~~~
key_version = 1*key_version_char
key_version_char = ALPHA / DIGIT / "_"
~~~

An algorithm and version combined is a "key ID", deliminated by `:` as per the following
ABNF {{!RFC5234}}:

~~~
key_id = key_algorithm ":" key_version
key_algorithm = "ed25519"
~~~

Additional key algorithms may be supported by future documents.

## Signing Events {#int-signing-events}

To sign an event:

1. Redact it ({{int-redactions}}).
2. Sign the result as an arbitrary object ({{int-signing-objects}}).

## Signing Arbitrary Objects {#int-signing-objects}

To sign an object:

1. Remove `signatures` and `unsigned`.
2. Encode the result with Canonical JSON ({{int-canonical-json}}).
3. Using the relevant ed25519 signing key (usually the server's), sign the object.
4. Encode that signature under `signatures` using unpadded base64 ({{int-unpadded-base64}}).

Note that `signatures` is an object with keys being the entity which did the signing and value
being the key ID to encoded signature pair. See {{int-pdu}} for details on the `signatures`
structure for events specifically.

## Checking Signatures {#int-checking-signatures}

If the `signatures` field is missing, doesn't contain the entity that is expected to have done
the signing (usually a server name), doesn't have a known key ID, or is otherwise structurally invalid
then the signature check fails.

If decoding the base64 fails, the check fails.

If the object is an event, redact ({{int-redactions}}) it before continuing.

If removing the `signatures` and `unsigned` properties, canonicalizing the JSON ({{int-canonical-json}}),
and verifying the signature fails, the check fails. Note that to verify the signature the server
may need to fetch another server's key first ({{int-transport-get-server-keys}}).

Otherwise, the check passes.

**TODO**: Which specific signatures are required? If a server has multiple signing keys, possibly
a combination of new and old, do we require all or some of them to sign?

# Canonical JSON {#int-canonical-json}

When signing a JSON object, such as an event, it is important that the bytes be ordered in
the same way for everyone. Otherwise, the signatures will never match.

To canonicalize a JSON object, use {{!RFC8785}}.

**TODO**: Matrix currently doesn't use RFC8785, but it should (or similar).

# Event Redactions {#int-redactions}

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

# Hashes

An event is covered by two hashes: a content hash and a reference hash. The content hash covers the
unredacted event to ensure it was not modified in transit. The reference hash covers the essential
fields of the event, including content hashes, and serves as the event's ID.

## Content Hash Calculation {#int-content-hashes}

1. Remove any existing `unsigned` and `signatures` fields.
   1. If calculating an LPDU's content hash, remove any existing `hashes` field as well.
   2. If *not* calculating an LPDU's content hash, remove any existing fields under `hashes` except
      for `lpdu`.
2. Encode the object using canonical JSON.
3. Hash the resulting bytes with SHA-256 {{!RFC6234}}.
4. Encode the hash using unpadded base64 ({{int-unpadded-base64}}).

## Reference Hash Calculation {#int-reference-hashes}

1. Redact the event.
2. Remove `signatures` and `unsigned` fields.
3. Encode the object using canonical JSON.
4. Hash the resulting bytes with SHA-256 {{!RFC6234}}.
5. Encode the hash using URL-safe unpadded base64 ({{int-unpadded-base64}}).

# Unpadded Base64 {#int-unpadded-base64}

Throughout this document, "unpadded base64" is used to represent binary values as strings. Base64 is
as specified by {{Section 4 of RFC4648}}, and "unpadded base64" simply removes any `=` padding from
the resulting string.

Implementations SHOULD accept input with or without padding on base64 values, where possible.

{{Section 5 of RFC4648}} describes *URL-safe* base64. The same changes are adopted here. Namely, the
62nd and 63rd characters are replaced with `-` and `_` respectively. The unpadded behaviour is as
described above.

# Hub Transfers

**TODO**: This section, if we want a single canonical hub in the room. Some expected problems in this
area are: who signs the transfer event? who *sends* the transfer event? how does a transfer start?

**TODO**: Is this section better placed in the MSC for now?

# Transport {#int-transport}

This document specifies a wire transport which uses JSON {{!RFC8259}} over HTTPS {{!RFC9110}}. Servers
MUST support a minimum of HTTP/2 {{!RFC9113}} and TLS 1.3 {{!RFC8446}}.

## TLS Certificates {#int-tls}

Servers MUST provide a TLS certificate signed by a known Certificate Authority. Requesting servers
are ultimately responsible for the Certificate Authorities they place trust in, however servers
SHOULD trust authorities which would commonly be trusted by an operating system or web browser.

## API Standards

### Requests and Responses {#int-transport-requests-responses}

All HTTP `POST` and `PUT` endpoints require the sending server to supply a (potentially empty) JSON
object as the request body. Requesting servers SHOULD supply a `Content-Type` header of `application/json`
for such requests.

All endpoints which require a server to respond with a JSON object MUST include a `Content-Type` header
of `application/json`.

All JSON data, in requests or responses, MUST be encoded using UTF-8 {{!RFC3629}}.

All endpoints in this document do *not* support trailing slashes on them. When such a request is
encountered, it MUST be handled as an unknown endpoint ({{int-unknown-endpoints}}). Examples include:

* `https://example.org/_matrix/path` - valid.
* `https://example.org/_matrix/path/` - unknown/invalid.
* `https://example.org//_matrix/path` - unknown/invalid (domain also can't have a trailing slash).
* `https://example.org//_matrix/path/` - doubly unknown/invalid.

Servers (both hub and participants) MUST implement all endpoints unless otherwise specified.

Most endpoints have a version number as part of the path. This version number is that endpoint's version,
allowing for breaking changes to be made to the schema of that endpoint. For clarity, the version number
is *not* representative of an API version.

### Errors {#int-transport-errors}

All errors are represented by an error code defined by this document and an accompanied HTTP status code.
It is possible for a HTTP status code to map to multiple error codes, and it's possible for an error
code to map to multiple HTTP status codes.

When a server is returning an error to a caller, it MUST use the most appropriate error response defined
by the endpoint. If no appropriate error response is specified, the server SHOULD use `M_UNKNOWN` as the
error code and `500 Internal Server Error` as the HTTP status code.

Errors are represented as JSON objects, requiring a `Content-Type: application/json` response header:

~~~ json
{
  "errcode": "M_UNKNOWN",
  "error": "Something went wrong."
}
~~~

`errcode` is required and denotes the error code. `error` is an optional human-readable description of
the error. `error` can be as precise or vague as the responding server desires - the strings in this
document are suggestions.

Some common error codes are:

* `M_UNKNOWN` - An unknown error has occurred.
* `M_FORBIDDEN` - The caller is not permitted to access the resource. For example, trying to join a room
  the user does not have an invite for.
* `M_NOT_JSON` - The request did not contain valid JSON. Must be accompanied by a `400 Bad Request` HTTP
  status code.
* `M_BAD_JSON` - The request did contain valid JSON, but it was missing required keys or was malformed in
   another way. Must be accompanied by a `400 Bad Request` HTTP status code.
* `M_LIMIT_EXCEEDED` - Too many requests have been sent. The caller should wait before trying the request
  again.
* `M_TOO_LARGE` - The request was too large for the receiver to handle.

### Unsupported Endpoints {#int-unknown-endpoints}

If a server receives a request for an unsupported or otherwise unknown endpoint, the server MUST respond
with an HTTP `404 Not Found` status code and `M_UNRECOGNIZED` error code. If the request was for a known
endpoint, but wrong HTTP method, a `405 Method Not Allowed` HTTP status code and `M_UNRECOGNIZED` error
code ({{int-transport-errors}}).

### Malformed Requests

If a server is expecting JSON in the request body but receives something else, it MUST respond with an
HTTP status code of `400 Bad Request` and error code `M_NOT_JSON` ({{int-transport-errors}}). If the
request contains JSON, and is for a known endpoint, but otherwise missing required keys or is malformed,
the server MUST respond with an HTTP status code of `400 Bad Request` and error code `M_BAD_JSON`
({{int-transport-errors}}). Where possible, `error` for `M_BAD_JSON` should describe the missing keys
or other parsing error.

### Transaction Identifiers {#int-txn-ids}

Where endpoints use HTTP `PUT`, it is typical for a "transaction ID" to be specified in the path
parameters. This transaction ID MUST ONLY be used for making requests idempotent - if a server receives
two (or more) requests with the same transaction ID, it MUST return the same response for each and only
process the request body once. It is assumed that requests using the same transaction ID also contain
the same request body between calls.

A transaction ID only needs to be unique per-endpoint and per-sending server. A server's transaction IDs
do not affect requests made by other servers or made to other endpoints by the same server.

### Rate Limiting

Servers SHOULD implement rate limiting semantics to reduce the risk of being overloaded. Endpoints which
support being rate limited are annotated in this document.

If a rate limit is encountered, the server MUST respond with an HTTP `429 Too Many Requests` status code
and `M_LIMIT_EXCEEDED` error code ({{int-transport-errors}}). If applicable, the server should additionally
include a `retry_after_ms` integer field on the error response to denote how long the caller should
wait before retrying, in milliseconds.

~~~ json
{
  "errcode": "M_LIMIT_EXCEEDED",
  "error": "Too many requests. Try again later.",
  "retry_after_ms": 10254
}
~~~

The exact rate limit mechanics are left as an implementation detail. A potential approach may be to
prevent repeated requests for the same resource at a high rate and ensuring a remote server does not
request more than a defined number of resources at a time.

## Resolving Server Names {#int-resolve-domain}

Before making an API request, the caller MUST resolve a server name ({{int-server-names}}) to an IP
address and port, suitable for HTTPS {{!RFC9110}} traffic.

A server MAY change the IP/port combination used for API endpoints using SRV DNS records {{!RFC2782}}.
Servers MAY additionally change which TLS certificate is presented by using `.well-known` delegation.

`.well-known` delegation (step 3 below) is recommended for its ease of configuration over SRV DNS records.

The target server MUST present a valid TLS certificate ({{int-tls}}) for the name described in each
step. Similarly, the requesting server MUST use an HTTP `Host` header matching the description in each
step.

Server developers should note that many of the DNS requirements for the steps below are typically handled
by the software language or library implicitly. It is rare that a DNS A record needs to be resolved manually,
for example.

Per {{int-server-names}}, a server name consists of `<hostname>[:<port>]`. The steps to convert that
server name to an IP address and port are:

1. If `<hostname>` is an IP literal, then that IP address is to be used together with the given port
   number, or 8448 if no port is given.

   TLS certificate: `<hostname>` (always without port)

   Host header: `<hostname>` or `<hostname>:<port>` if a port was specified

2. If `<hostname>` is not an IP literal, and an explicit `<port>` is present, resolve `<hostname>` to
   an IP address using CNAME {{!RFC1034}} {{!RFC2181}}, AAAA {{!RFC3596}}, or A {{!RFC1035}} DNS
   records. Requests are made to the resolved IP address and port number.

   TLS certificate: `<hostname>` (always without port)

   Host header: `<hostname>:<port>`

3. If `<hostname>` is not an IP literal, a regular (non-Matrix) HTTPS request is made to
   `https://<hostname>/.well-known/matrix/server`, expecting the schema defined by {{int-wellknown}}.
   If the response is invalid (bad/not JSON, missing properties, non-200 response, etc), skip to Step 4.
   If the response is valid, the `m.server` property is parsed as `<delegated_hostname>[:<delegated_port>]`.

   1. If `<delegated_hostname>` is an IP literal, then that IP address is to be used together with the
      given port number, or 8448 if no port is given.

      TLS certificate: `<delegated_hostname>` (always without port)

      Host header: `<delegated_hostname>` or `<delegated_hostname>:<delegated_port>` if a port was specified

   2. If `<delegated_hostname>` is not an IP literal, and `<delegated_port>` is present, resolve
      `<delegated_hostname>` to an IP address using CNAME, AAAA, or A DNS records. Requests are made to the
      resolved IP address and port number.

      TLS certificate: `<delegated_hostname>` (always without port)

      Host header: `<delegated_hostname>:<delegated_port>`

   3. If `<delegated_hostname>` is not an IP literal and no `<delegated_port>` is present, an SRV DNS
      record is resolved for `_matrix._tcp.<delegated_hostname>`. This may result in another hostname
      and port to be resolved using AAAA or A DNS records. Requests are made to the resolved IP address
      and port number.

      TLS certificate: `<delegated_hostname>`

      Host header: `<delegated_hostname>` (without port)

   4. If no SRV record is found, an IP address is resolved for `<delegated_hostname>` is resolved using
      CNAME, AAAA, or A DNS records. Requests are made to the resolved IP address with port number 8448.

      TLS certificate: `<delegated_hostname>`

      Host header: `<delegated_hostname>` (without port)

4. If the `.well-known` call from Step 3 resulted in an invalid response, an SRV DNS record is resolved
   for `_matrix._tcp.<hostname>`. This may result in another hostname and port to be resolved using AAAA
   or A DNS records. Requests are made to the resolved IP address and port number.

   TLS certificate: `<hostname>` (always without port)

   Host header: `<hostname>` (without port)

5. If the `.well-known` call from Step 3 resulted in an invalid response, and the SRV record from Step 4
   was not found, and IP address is resolved using CNAME, AAAA, or A DNS records. Requests are made to the
   resolved IP address and port 8448.

   TLS certificate: `<hostname>` (always without port)

   Host header: `<hostname>` (without port)

We require `<[delegated_]hostname>` rather than `<srv_hostname>` in Steps 3.3 and 4 for the following reasons:

1. DNS is largely insecure (not all domains use DNSSEC {{?RFC9364}}), so the target of the SRV record must
   prove it is a valid delegate/target for `<[delegated_]hostname>` via TLS.
2. {{Section 6.2.1 of RFC6125}} recommends this approach, and is consistent with other applications
   which use SRV records (such as {{Section 13.7.2.1 of RFC6120}}/XMPP).

Server implementations and owners should additionally note that the target of a SRV record MUST NOT be a CNAME,
as per RFC 2782 {{!RFC2782}}:

> the name MUST NOT be an alias (in the sense of RFC 1034 or RFC 2181)

{{!RFC1034}} {{!RFC2181}}

### `GET /.well-known/matrix/server` {#int-wellknown}

Used by the server name resolution approach to determine a delegated hostname for a given server. 30x HTTP
redirection MUST be followed, though loops SHOULD be avoided. Normal X.509 certificate validation is applied
to this endpoint (not the specific validation required by the server name resolution steps) {{?RFC5280}}.

This endpoint MAY be implemented by servers (it is optional).

**Rate-limited**: No.

**Authentication required**: No.

This HTTP endpoint does not specify any request parameters or body.

`200 OK` response:

~~~ json
{
   "m.server": "delegated.example.org:8448"
}
~~~

`m.server` is a required response field. Responses SHOULD have a `Content-Type` HTTP header of
`application/json`, however servers parsing the response should assume that the body is JSON regardless
of `Content-Type` header. Failures in parsing the JSON or otherwise invalid data that prevents parsing
MUST NOT result in discovery failure. Instead, the caller is expected to move on to the next step of
the name resolution approach.

Cache control headers SHOULD be respected on a `200 OK` response. Callers SHOULD impose a maximum
cache time of 48 hours, regardless of cache control headers. A default of 24 hours SHOULD be used
when no cache control headers are present.

Error responses (non-200) SHOULD be cached for no longer than 1 hour. Callers SHOULD exponentially
back off (to a defined limit) upon receiving repeated error responses.

## Request Authentication {#int-transport-auth}

Most endpoints in this document require authentication to prove which server is making the request.
This is done using public key digital signatures.

The request method, target, and body are represented as a JSON object, signed, and appended as an HTTP
`Authorization` header with an auth scheme of `X-Matrix`.

The object to be signed is:

~~~ json
{
   "method": "GET",
   "uri": "/path/to/endpoint?with_qs=true",
   "origin": "requesting.server.name.example.org",
   "destination": "target.server.name.example.org",
   "content": {"json_request_body": true}
}
~~~

`method` is the HTTP request method, capitalized. `uri` is the full request path, beginning with the
leading slash and containing the query string (if present). `uri` does not contain the `https:` scheme
or hostname.

**TODO**: Define an ordering algorithm for the query string (if we need to?).

`origin` and `destination` are the sender and receiver server names ({{int-server-names}}), respectively.

`content` is the JSON-encoded request body. When a request doesn't contain a body, such as in `GET`
requests, use an empty JSON object.

That object is then signed ({{int-signing-objects}}) by the requesting server. The resulting signature
is appended as an `Authentication` HTTP header on the request:

~~~
GET /path/to/endpoint?with_qs=true
Authorization: X-Matrix origin="requesting.server.name.example.org",
   destination="target.server.name.example.org",
   key="ed25519:0",
   sig="<unpadded base64 encoded signature>"
Content-Type: application/json

{"json_request_body": true}
~~~

Linebreaks within `Authorization` are for clarity and are non-normative.

The format of the Authorization header matches {{Section 11.4 of RFC9110}}. The header begins with an
authorization scheme of `X-Matrix`, followed by one or more spaces, followed by an (unordered)
comma-separated list of parameters written as name=value pairs. The names are case insensitive, though
the values are. The values must be enclosed in quotes if they contain characters which are not allowed
in a `token`, as defined by {{Section 5.6.2 of RFC9110}}. If a value is a valid `token` it may not be
enclosed in quotes. Quoted values MAY contain backslash-escaped characters. When parsing the header,
the recipient must unescape the characters.

The exact parameters are:

* `origin` - The name of the sending server. MUST match the `origin` in the signed JSON.
* `destination` - The name of the receiving server. MUST match the `destination` in the signed JSON.
* `key` - The ID, including algorithm name, of the sending server's signing key used to sign the request.
* `signature` - The unpadded base64 ({{int-unpadded-base64}}) encoded signature from step 2.

Unknown parameters are ignored and MUST NOT result in authentication errors.

A receiving server validates the Authorization header by composing the JSON object represented above
and checking the sender's signature ({{int-checking-signatures}}). Note that to comply with
{{int-checking-signatures}} the receiver may need to append a `signatures` field to the JSON object
manually. All signatures MUST use an unexpired key at the time of the request
({{int-transport-keys-validity}}).

A server with multiple signing keys SHOULD include an `Authorization` header for each signing key.

If an endpoint requires authentication, servers MUST:
* Validate all presented `Authorization` headers.
* Ensure at least one `Authorization` header is present.

If either fails (lack of headers, or any of the headers fail validation), the request MUST be rejected
with an HTTP `401 Unauthorized` status code and `M_FORBIDDEN` error code ({{int-transport-errors}}):

~~~ json
{
   "errcode": "M_FORBIDDEN",
   "error": "Signature error on request."
}
~~~

If an endpoint does *not* require authentication, `Authorization` headers are ignored entirely.

Responses from a server are authenticated using TLS and do not have additional signing requirements.

### Retrieving Server Keys {#int-transport-get-server-keys}

A server's signing keys are published under `/_matrix/key/v2/server` ({{int-api-self-key}}) and can
be queried through notary servers in two ways: {{int-api-notary-query}} and {{int-api-notary-query-bulk}}.
Notary servers implicitly call `/_matrix/key/v2/server` when queried, signing and caching the response
for some time. This allows the target server to offline without affecting their previously sent events.

The approach used here is borrowed from the Perspectives Project {{PerspectivesProject}}, modified to
cover the server's ed25519 keys and to use JSON instead of XML. The advantage of this system is it allows
each server to pick which notaries it trusts, and can contact multiple notaries to corroborate the keys
returned by any given notary.

Servers SHOULD attempt to contact the target server directly before using a notary server.

Note that these endpoints operate outside the context of a room: a server does not need to participate
in any shared rooms to be used as a notary by another server, and does not need to use the hub as a
notary.

#### Validity {#int-transport-keys-validity}

A server's keys are only valid for a short time, denoted by `valid_until_ts`. Around the `valid_until_ts`
timestamp, a server would re-fetch the server's keys to discover any changes. In the vast majority of
cases, only `valid_until_ts` changes between requests (keys are long-lived, but validated frequently).

`valid_until_ts` MUST be handled as the lesser of `valid_until_ts` and 7 days into the future, preventing
attackers from publishing long-lived keys that are unable to be revoked. Servers SHOULD use a timestamp
approximately 12 hours into the future when responding with their keys.

**TODO**: What does it mean to require events have an `origin_server_ts` which is less than that of
`valid_until_ts`? Do we reject the event, soft-fail it, or do something else? Do we only do this on the
hub?

#### `GET /_matrix/key/v2/server` {#int-api-self-key}

Retrieves the server's signing keys. The server can have any number of active or inactive keys at a
time, but SHOULD have at least 1 active key at all times.

**Rate-limited**: No.

**Authentication required**: No.

This HTTP endpoint does not specify any request parameters or body.

`200 OK` response:

~~~ json
{
   "server_name": "example.org",
   "valid_until_ts": 1686776437176,
   "m.linearized": true,
   "verify_keys": {
      "ed25519:0": {
         "key": "<unpadded base64 encoded public key>"
      }
   },
   "old_verify_keys": {
      "ed25519:bad": {
         "expired_ts": 1586776437176,
         "key": "<unpadded base64 encoded public key>"
      }
   },
   "signatures": {
      "example.org": {
         "ed25519:0": "<unpadded base64 encoded signature>"
      }
   }
}
~~~

`server_name` MUST be the name of the server ({{int-server-names}}) which is returning the keys.

`valid_until_ts` is the integer timestamp (milliseconds since Unix epoch) for when the server's keys
should be re-fetched. See {{int-transport-keys-validity}}.

`m.linearized` is an optional boolean, but SHOULD be set to `true`. Semantics for `false` and not
being present apply to contexts outside of this document.

`verify_keys` are the current signing keys for the server, keyed by key ID ({{int-signing}}). The
object value for each key ID under `verify_keys` is simply the `key`, consisting of the unpadded
base64 encoded public key matching that algorithm and version.

`old_verify_keys` are similar to `verify_keys`, but have an additional required `expired_ts` property
to denote when the key ceased usage. This overrides `valid_until_ts` for the purposes of
{{int-transport-keys-validity}} at an individual key level.

**TODO**: What about events sent with `old_verify_keys`?

For request authentication ({{int-transport-auth}}), only keys listed under `verify_keys` are honoured.
If another key is referenced by the `Authorization` headers, the request fails authentication.

Notaries SHOULD cache a 200 OK response for half of its lifetime to avoid serving stale values.
Responding servers SHOULD avoid returning responses which expire in less than an hour to avoid
repeated requests. Requesting servers SHOULD limit how frequently they query for keys to avoid
flooding a server with requests.

If the server fails to respond to this request, notaries SHOULD continue to return the last response
they received from the server so that the signatures of old events can still be checked, even if that
response is no longer considered valid ({{int-transport-keys-validity}}).

Servers are capable of rotating their keys without populating `old_verify_keys`, though this can cause
reliability issues if other servers don't see both keys. Notaries SHOULD cache responses with distinct
key IDs indefinitely. For example, if a server has `ed25519:0` and `ed25519:1` on its first response,
and a later response returns `ed25519:1` and `ed25519:2`, the notary should cache both responses. This
gives servers an ability to validate `ed25519:0` for old events in a room.

#### `GET /_matrix/key/v2/query/:serverName` {#int-api-notary-query}

This is one of two endpoints for querying a server's keys through another server. The notary (receiving)
server will attempt to refresh its cached copy of the target server's keys through `/_matrix/key/v2/server`,
falling back to any cached values if needed.

**Rate-limited**: No.

**Authentication required**: No.

Path parameters:

* `:serverName` - the target server's name ({{int-server-names}}) to retrieve keys for.

Query parameters:

* `minimum_valid_until_ts` (integer; optional) - The time in milliseconds since the Unix epoch the
  target server's keys will need to be valid until to be useful to the caller. If not specified the
  notary server's current time will be used.

Request body: None applicable.

`200 OK` response:

~~~ json
{
   "server_keys": [
      {/* server key */}
   ]
}
~~~

`server_keys` is the array of keys (see {{int-api-self-key}} response format) for the target server.
If the target server could not be reached and the notary has no cached keys, this array is empty. If
the keys do not meet `minimum_valid_until_ts` per {{int-transport-keys-validity}}, they are not included.

The notary server MUST sign each key returned in `server_keys` by at least one of its own signing keys.
The calling server MUST validate all signatures on the objects.

#### `POST /_matrix/key/v2/query` {#int-api-notary-query-bulk}

A bulk version of `/_matrix/key/v2/query/:serverName` ({{int-api-notary-query}}). The same behaviour
applies to this endpoint.

**Rate-limited**: No.

**Authentication required**: No.

Path parameters: None applicable.

Query parameters: None applicable.

Request body:

~~~ json
{
   "server_keys": {
      "example.org": {
         "ed25519:0": {
            "minimum_valid_until_ts": 1686783382189
         }
      }
   }
}
~~~

`server_keys` is required and is the search criteria. The object value is first keyed by server name
which maps to another object keyed by Key ID, mapping to the specific criteria. If no key IDs are
given in the request, all of the server's known keys are queried. If no servers are given in the
request, the response MUST contain an empty `server_keys` array.

`minimum_valid_until_ts` holds the same meaning as in {{int-api-notary-query}}.

`200 OK` response:

Same as {{int-api-notary-query}} with the following added detail:

Responding servers SHOULD only return signed key objects for the key IDs requested by the caller, however
servers MAY respond with more keys than requested. The caller is expected to filter the response if
needed.

## Sending Events {#int-transport-send-events}

Events accepted into the room by a hub server must be sent to all other servers in that room. Similarly,
participant servers need a way to send partial events through the hub server, as mentioned by {{int-lpdu}}.

A single endpoint is used for all rooms on either server, and can contain both fully-formed PDUs
({{int-pdu}}) or Linearized PDUs (partial events; {{int-lpdu}}) depending on the server's role in the
applicable room.

A typical event send path will be:

~~~ aasvg
+-----+                +---------------+     +---------------+
| Hub |                | Participant1  |     | Participant2  |
+-----+                +---------------+     +---------------+
   |                           |                     |
   |                           | Create LPDU         |
   |                           |-----------+         |
   |                           |           |         |
   |                           |<----------+         |
   |                           |                     |
   |          PUT /send/:txnId |                     |
   |<--------------------------|                     |
   |                           |                     |
   | Append PDU fields         |                     |
   |-----------------+         |                     |
   |                 |         |                     |
   |<----------------+         |                     |
   |                           |                     |
-------------------- CONCURRENT REQUESTS ---------------------
   |                           |                     |
   | PUT /send/:txnId          |                     |
   |-------------------------->|                     |
   |                           |                     |
   | PUT /send/:txnId          |                     |
   |------------------------------------------------>|
   |                           |                     |
~~~

`PUT /send/:txnId` is shorthand for {{int-api-send-txn}}.

Hubs which generate events would skip to the point where they create a fully-formed PDU and send it
out to all other participants.

### `PUT /_matrix/federation/v2/send/:txnId` {#int-api-send-txn}

Sends (L)PDUs ({{int-pdu}}, {{int-lpdu}}) to another server. The sending server MUST wait for a
`200 OK` response from the receiver before sending another request with a different `:txnId`.

**Implementation note**: Currently this endpoint doesn't actually exist. Use
`PUT /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/send/:txnId`
when testing against other Linearized Matrix implementations. This string may be updated later to
account for breaking changes.

**TODO**: Remove implementation notes.

**Rate-limited**: No.

**Authentication required**: Yes.

Path parameters:

* `:txnId` - the transaction ID ({{int-txn-ids}}) for the request.

Query parameters: None applicable.

Request body:

~~~ json
{
   "edus": [{/* TODO: Define EDUs */}],
   "pdus": [
      {/* Either an LPDU or PDU */}
   ]
}
~~~

**TODO**: Describe EDUs.

`edus` are the Ephemeral Data Units to send. If no EDUs are being sent, this field MAY be excluded
from the request body.

`pdus` are the events/PDUs ({{int-pdu}}) and LPDUs ({{int-lpdu}}) to send to the server. Whether
it's an LPDU or PDU depends on the sending server's role in that room: if they are a non-hub server,
it will be an LPDU.

Each event in the `pdus` array gets processed as such:

1. Identify the room ID for the event. The exact format of the event can differ between room versions,
   however currently this would be done by extracting the `room_id` property.

   1. If that room ID is invalid/not found, the event is rejected.
   2. If the server is not participating in the room, the event is dropped/skipped.

2. If the event is an LPDU and the receiving server is the hub, the additional PDU fields are appended
   before continuing.

3. If the event is an LPDU and the receiving server is not the hub, the event is dropped/skipped.

4. The checks defined by {{int-receiving-events}} are performed.

5. If the event still hasn't been dropped/rejected, it is appended to the room. For participant servers,
   this may mean it's queued for sending to local clients.

Server implementation authors should note that these steps can be condensed, but are expanded here
for specification purposes. For example, an LPDU's signature can/will fail without ever needing to
append the PDU fields first - the server can skip some extra work this way.

`200 OK` response:

~~~ json
{
   "failed_pdus": {
      "$eventid": {
         "error": "Invalid event format"
      },
      "$eventid": {
         "error": "@alice:example.org cannot send m.room.power_levels"
      }
   }
}
~~~

The receiving server MUST NOT send a `200 OK` response until all events have been processed. Servers
SHOULD NOT block responding to this endpoint on sending accepted events to local clients or other
participant servers, as doing so could lead to a lengthy backlog of events waiting to be sent.

Sending servers SHOULD apply/expect a timeout and retry the exact same request with the same transaction
ID until they see a `200 OK` response. If the sending server attempts to send a different transaction
ID from the one already in flight, the receiving server MUST respond with a `400 Bad Request` HTTP
status code and `M_BAD_STATE` error code ({{int-transport-errors}}). Receiving servers SHOULD continue
processing requests to this endpoint event after the sender has disconnected/timed out, but SHOULD NOT
process the request multiple times due to the transaction ID ({{int-txn-ids}}).

`failed_pdus` is an object mapping event ID ({{int-pdu}}) to error string. Event IDs are based upon
the received object, not the final/complete object. For example, if an LPDU is sent, gets its PDU
fields appended, and fails event authorization, then the error would be for the event ID of the LPDU,
not the fully-formed PDU. This is to allow the sender to correlate what they sent with errors.

The object for each event ID MUST contain an `error` string field, representing the human-readable
reason for an event being rejected.

Events which are dropped/ignored or accepted do *not* appear in `failed_pdus`.

**TODO**: Should we also return fully-formed PDUs for the LPDUs we received?

## Event and State APIs

When a participant in the room is missing an event, or otherwise needs a new copy of it, it can retrieve
that event from the hub server. Similar mechanics apply for getting state events, current state of a room,
and backfilling scrollback in a room.

All servers are required to implement all endpoints ({{int-transport-requests-responses}}), however
only hub servers are guaranteed to have the full history/state for a room. While other participant
servers might have history, they SHOULD NOT be contacted due to the high likelihood of a Not Found-style
error.

### `GET /_matrix/federation/v2/event/:eventId`

Retrieves a single event.

**Implementation note**: Currently this endpoint doesn't actually exist. Use
`GET /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/event/:eventId`
when testing against other Linearized Matrix implementations. This string may be updated later to
account for breaking changes.

**TODO**: Remove implementation notes.

**Rate-limited**: Yes.

**Authentication required**: Yes.

Path parameters:

* `:eventId` - the event ID ({{int-pdu}}) to retrieve. Note that event IDs are typically reference
  hashes ({{int-reference-hashes}}) of the event itself, which includes the room ID. This makes
  event IDs globally unique.

Query parameters: None applicable.

Request body: None applicable.

`200 OK` response:

~~~ json
{
   /* the event */
}
~~~

The response body is simply the event ({{int-pdu}}) itself, if the requesting server has reasonable
visibility of the event ({{int-calc-event-visibility}}). When the server can see an event but not the
contents, the event is served redacted ({{int-redactions}}) instead.

If the event isn't known to the server, or the requesting server has no reason to know that the event
even exists, a `404 Not Found` HTTP status code and `M_NOT_FOUND` error code ({{int-transport-errors}})
is returned.

The returned event MUST be checked before being used by the requesting server ({{int-receiving-events}}).
This endpoint MUST NOT return LPDUs ({{int-lpdu}}), instead treating such events as though they didn't
exist.

### `GET /_matrix/federation/v1/state/:roomId` {#int-api-get-state}

Retrieves a snapshot of the room state ({{int-state-events}}) at the given event. This is typically
most useful when a participant server prefers to store minimal information about the room, but still
needs to offer context to its clients.

**Rate-limited**: Yes.

**Authentication required**: Yes.

Path parameters:

* `:roomId` - the room ID ({{int-room-id}}) to retrieve state in.

Query parameters:

* `event_id` (string; required) - The event ID ({{int-pdu}}) to retrieve state at.

Request body: None applicable.

`200 OK` response:

~~~ json
{
   "auth_chain": [
      {/* event */}
   ],
   "pdus": [
      {/* event */}
   ]
}
~~~

The returned room state is in two parts: the `pdus`, consisting of the events which represent "current
state" ({{int-state-events}}) prior to considering state changes induced by the event in the original
request, and `auth_chain`, consisting of the events which make up the `auth_events` ({{int-auth-selection}})
for the `pdus` and the `auth_events` of those events, recursively.

The `auth_chain` will eventually stop recursing when it reaches the `m.room.create` event, as it cannot
have any `auth_events`.

For example, if the requested event ID was an `m.room.power_levels` event, the returned state would be
as if the new power levels were not applied.

Both `auth_chain` and `pdus` contain event objects ({{int-pdu}}).

If the requesting server does not have reasonable visibility on the room ({{int-calc-event-visibility}}),
or either the room ID or event ID don't exist, a `404 Not Found` HTTP status code and `M_NOT_FOUND`
error code ({{int-transport-errors}}) is returned. The same error is returned if the event ID doesn't
exist in the requested room ID.

Note that the requesting server will generally always have visibility of the `auth_chain` and `pdu`
events, but may not be able to see their contents. In this case, they are redacted ({{int-redactions}})
before being served.

The returned events MUST be checked before being used by the requesting server ({{int-receiving-events}}).
This endpoint MUST NOT return LPDUs ({{int-lpdu}}), instead treating such events as though they didn't
exist.

### `GET /_matrix/federation/v1/state_ids/:roomId`

This performs the same function as {{int-api-get-state}} but returns just the event IDs instead.

**Rate-limited**: Yes.

**Authentication required**: Yes.

Path parameters:

* `:roomId` - the room ID ({{int-room-id}}) to retrieve state in.

Query parameters:

* `event_id` (string; required) - The event ID ({{int-pdu}}) to retrieve state at.

Request body: None applicable.

`200 OK` response:

~~~ json
{
   "auth_chain_ids": ["$event1", "$event2"],
   "pdu_ids": ["$event3", "$event4"]
}
~~~

See {{int-api-get-state}} for behaviour. Note that `auth_chain` becomes `auth_chain_ids` when using
this endpoint, and `pdus` becomes `pdu_ids`.

### `GET /_matrix/federation/v2/backfill/:roomId`

Retrieves a sliding window history of previous events in a given room.

**Implementation note**: Currently this endpoint doesn't actually exist. Use
`GET /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/backfill/:roomId`
when testing against other Linearized Matrix implementations. This string may be updated later to
account for breaking changes.

**TODO**: Remove implementation notes.

**Rate-limited**: Yes.

**Authentication required**: Yes.

Path parameters:

* `:roomId` - the room ID ({{int-room-id}}) to retrieve events from.

Query parameters:

* `v` (string; required) - The event ID ({{int-pdu}}) to start backfilling from.
* `limit` (integer; required) - The maximum number of events to return, including `v`.

Request body: None applicable.

`200 OK` response:

~~~ json
{
   "pdus": [
      {/* event */}
   ]
}
~~~

The number of returned `pdus` MUST NOT exceed the `limit` provided by the caller. `limit` SHOULD have
a maximum value imposed by the receiving server. `pdus` contains the events ({{int-pdu}}) preceeding
the requested event ID (`v`), including `v`. `pdus` is ordered from oldest to newest.

If the requesting server does not have reasonable visibility on the room ({{int-calc-event-visibility}}),
or either the room ID or event ID don't exist, a `404 Not Found` HTTP status code and `M_NOT_FOUND`
error code ({{int-transport-errors}}) is returned. The same error is returned if the event ID doesn't
exist in the requested room ID.

If the requesting server does have visibility on the returned events, but not their contents, they
are redacted ({{int-redactions}}) before being served.

The returned events MUST be checked before being used by the requesting server ({{int-receiving-events}}).
This endpoint MUST NOT return LPDUs ({{int-lpdu}}), instead treating such events as though they didn't
exist.

## TODO: Remainder of Transport

**TODO**: This section.

Topics:
* Media/content repo (images, videos, attachments, etc)
* EDUs (typing notifications, receipts, presence)
* Device management & to-device messaging
* Query APIs (alias resolution, profiles)
* Encryption APIs

Notably/deliberately missing APIs are:

* `get_missing_events` - this is used by DAG servers only
* Public room directory
* Timestamp-to-event API
* All of 3rd party invites
* All of Spaces
* OpenID API

# TODOs & Open Questions

* Should we include `/_matrix/federation/v1/version` in here? It's used by federation testers, but not
really anything else.

# Security Considerations

**TODO**: Expand upon this section.

With the combined use of MLS and server-side enforcement, the server theoretically has an ability to
add a malicious device to the MLS group and receive decryptable messages. Authenticity of devices needs
to be established to ensure a user's devices are actually a user's devices.

**TODO**: Should we bring Matrix's cross-signing here?

Servers retain the ability to control/puppet their own users due to no strong cryptographic link between
the sending device and the event which gets emitted.

# IANA Considerations

The `m.*` namespace likely needs formal registration in some capacity.

The `I.*` namespace likely needs formal registration in some capacity.

Port 8448 may need formal registration.

The SRV service name `matrix` may need re-registering, or a new service name assigned.

The `.well-known/matrix` namespace is already registered for use by The Matrix.org Foundation C.I.C.

--- back

# Acknowledgments
{:numbered="false"}

Thank you to the Matrix Spec Core Team (SCT), and in particular Richard van der Hoff, for
exploring how Matrix rooms could be represented as a linear structure, leading to this document.
