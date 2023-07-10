# Implementation notes for Matrix developers

This document is primarily intended for Matrix developers like the Spec Core Team (SCT): folks who already
likely know about the inner workings of Matrix and want to know how Linearized Matrix is different from
spec.matrix.org's definition of Matrix.

If you're not already familiar with Matrix, or are trying to implement Linearized Matrix from scratch, please
review the I-D instead.

**This is a living document.** Please track changes aggressively.

## Architecture

Linearized Matrix (LM) operates at the per-room level, creating a cluster of servers which do not support DAG
operations natively. Routing within LM is hub-and-spoke, where a hub server converts partial events from
"participant" servers into real events that work with DAG servers. DAG-capable servers in the room *do not*
need to route their events through the hub server.

A "participant server" is a non-DAG capable, non-hub, homeserver in the room.

This is the send path for participant->world:

```
+-------------+          +-----+                            +-----------+ +-----------+
| Participant |          | Hub |                            | Synapse1  | | Conduit1  |
+-------------+          +-----+                            +-----------+ +-----------+
       |                    |                                     |             |
       | Partial event      |                                     |             |
       |------------------->|                                     |             |
       |                    |                                     |             |
       |                    | Add fields to form normal PDU       |             |
       |                    |------------------------------       |             |
       |                    |                             |       |             |
       |                    |<-----------------------------       |             |
       |                    |                                     |             |
       |                    | Internally send PDU                 |             |
       |                    |--------------------                 |             |
       |                    |                   |                 |             |
       |                    |<-------------------                 |             |
       |                    |                                     |             |
       |    Send PDU (echo) |                                     |             |
       |<-------------------|                                     |             |
       |                    |                                     |             |
       |                    | Send PDU                            |             |
       |                    |------------------------------------>|             |
       |                    |                                     |             |
       |                    | Send PDU                            |             |
       |                    |-------------------------------------------------->|
       |                    |                                     |             |
```

Synapse1 and Conduit1 are considered "DAG-capable" servers.

If Synapse1 were to want to send an event, it does so just as it does today, though avoids making contact to the
participant server directly (as the participant will reject the request due to not being the hub):

```
+-------------+   +-----+                             +-----------+               +-----------+
| Participant |   | Hub |                             | Synapse1  |               | Conduit1  |
+-------------+   +-----+                             +-----------+               +-----------+
       |             |                                      |                           |
       |             |                                      | Internally send PDU       |
       |             |                                      |--------------------       |
       |             |                                      |                   |       |
       |             |                                      |<-------------------       |
       |             |                                      |                           |
       |             |                                      | Send PDU                  |
       |             |                                      |-------------------------->|
       |             |                                      |                           |
       |             |                             Send PDU |                           |
       |             |<-------------------------------------|                           |
       |             |                                      |                           |
       |             | Run linearization on DAG event       |                           |
       |             |-------------------------------       |                           |
       |             |                              |       |                           |
       |             |<------------------------------       |                           |
       |             |                                      |                           |
       |    Send PDU |                                      |                           |
       |<------------|                                      |                           |
       |             |                                      |                           |
```

On the hub server, the room is an **append-only** singly linked list. Events are appended in order of receipt. As
part of linearization the hub may need to accept/generate "filler" events to handle cases where state res kicks a
user out of the room or invalidates prior events, for example.

In short, LM will treat accepted data as forever accepted. This is to ensure maximum compatibility with MLS, a
requirement for encryption within MIMI. LM can support Olm/Megolm as well, but how it does so is out of scope for
MIMI.

Participant servers are not required to do anything beyond trusting the hub server to send events to it, but are
encouraged to track room state locally to validate the hub is behaving correctly.

## Room Version

The majority of mechanics are based upon [MSC3820: Room version 11](https://github.com/matrix-org/matrix-spec-proposals/pull/3820).

Changes from v11 are:

* Event format: `hashes` has a new structure, and `hub_server` is a new top level property.
* Grammar: `I.` as a prefix is now reserved for use by the IETF specification process.
* Signing: an intermediary "Linearized PDU" (LPDU) event is incorporated into the overall event/PDU signatures.
* Clarification: size limits are checked under "checks performed upon receipt of a PDU".
* Auth rules: all rules relating to `join_authorised_via_users_server` and restricted rooms are removed.
  * This is not intentional, so just be careful in what you send in unstable room versions for now.
* Auth rules: `third_party_invite` is not checked on `m.room.member` events. 3rd party invites do not exist in LM.
* Auth rules: `notifications.*` is not checked as part of `m.room.power_levels` checks.
* Canonical JSON: we use [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785).
  * For the majority of cases, Matrix's existing canonical JSON implementation is *close enough*.
* Content hash: the algorithm has changed to account for LPDU hashes.
* Redactions: `hub_server` is preserved as a top-level field.
* Event format: `depth` has no meaning. It is additionally removed from the redaction algorithm.

These are adopted as the unstable room version `org.matrix.i-d.ralston-mimi-linearized-matrix.02`.

Note that there's also a `org.matrix.i-d.ralston-mimi-linearized-matrix.00` room version out there, but is no longer
in use.

### Event Format / LPDU

Linearized PDUs (LPDUs) are partially-formed events generated by participant servers before sending them off to the
hub server, which adds fields to make them real events.

An LPDU has the same fields as a normal PDU, with the following changes:

* `auth_events` is *not* included, because the participant doesn't have reasonable visibility on "current state".
* `prev_events` is *not* included, because the participant doesn't track room history unless it wants to.
* `hashes` *only* has `lpdu` under it.
* `hub_server` is added to denote which hub server the participant is sending through.

This partial is then signed by the participant. Note that the `lpdu` hashes cover a content hash of the LPDU itself.

For example:

```json
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
    }
  },
  "signatures": {
    "first.example.org": {
      "ed25519:1": "<unpadded base64 signature covering whole event>"
    }
  },
  "unsigned": {
    "arbitrary": "fields"
  }
}
```

The hub then appends the missing fields, hashes it, and signs it:


```json
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
```

`prev_events` for events created by the hub *should* always have exactly 1 event ID. If the server is dual-stack then
it may have multiple.

The presence of `hub_server` denotes the event was sent by a LM server. If not present, the event is assumed to be
sent by a DAG-capable server.

When `hub_server` is present, only the signature implied by the domain name of the `sender` is special (as it signs
the LPDU). All other signatures are expected to be validated as though they sign the fully-formed PDU, per normal.

### Content Hash

The only change is made to Step 1 of the content hashing algorithm. The full algorithm is:

1. Remove any existing `unsigned` and `signatures` fields.
   1. If calculating an LPDU's content hash, remove any existing `hashes` field as well.
   2. If *not* calculating an LPDU's content hash, remove any existing fields under `hashes` except
      for `lpdu`.
2. Encode the object using canonical JSON.
3. Hash the resulting bytes with SHA-256.
4. Encode the hash using unpadded base64.

## Request Authentication

There are largely clarifications to how request authentication works. Namely:

* A 401 M_FORBIDDEN error is returned when improperly authenticated.
* Only one of the sender's signing keys needs to be used, but senders should send as many as possible (if the server
  has multiple signing keys).
* A failure in any one `Authorization` header is treated as fatal for the whole request.
* `GET` requests, or those without a request body, are represented as `{}` in the signed JSON.
* `destination` in the `Authorization` header is formally required, though backwards compatible with Matrix today.

This is meant to be compatible with [MSC4029](https://github.com/matrix-org/matrix-spec-proposals/pull/4029), when
MSC4029 has real content in it.

## Linearization Algorithm

The specific mechanics of this algorithm are undefined. The rough idea is that when a DAG-capable server becomes
involved in the room that it get transfered hub status as well, if the hub isn't already pointing to a DAG-capable
server. That DAG-capable server then does local linearization based on the to-be-defined algorithm.

Characteristics of the algorithm are:
* Events are always appended to the HEAD of the array (for LM), or at least operates like that over the API surface.
* Because eventual consistency and state res can cause problems, "fix it" events might need to be sent. For example,
  "actually, Alice is banned now" events. Note that this will also need considering for state resets.

Identifying events which need linearizing is not yet decided, but it'll likely be some combination/either of the
`hub_server` and `prev_events` (when >1 value) properties. For example, when a "fork" happens (event appended to
somewhere other than the HEAD of the list) via `prev_events`, state res and other algorithms kick in.

Note that the implication here is that *all* DAG-capable servers would be expected to become dual stack servers,
supporting the semantics/details of LM servers. All DAG-capable servers can become hubs.

## Hub Transfers

Not yet decided on how this works. It's possible we want to support situations where there's multiple hubs in a room.

Rough theory is we can advertise that a server supports being a hub server (or is a DAG-capable server) somewhere,
and participants can choose their favourite, creating small clusters of LM servers in the room.

## EDU Changes

* `m.device_list_update` has changed shape entirely:
  ```json
  {
    "type": "m.device_list_update",
    "sender_id": "@alice:example.org",
    "content": {
        "changed": [/* Device Objects */],
        "removed": [/* Device IDs */]
    }
  }
  ```

  A "device object" is the response body for `/user/:userId/device/:deviceId`.

* `m.direct_to_device` has lost some fields under `content`, and no longer carries multiple messages
  per EDU.

  ```json
  {
    "type": "m.direct_to_device",
    "sender": "@alice:example.org",
    "content": {
        "target": "@bob:example.org",
        "target_device": "ABCD",
        "message_type": "m.room.encrypted",
        "message": {
          /* message_type-specific schema */
        }
    }
  }
  ```

## HTTP API Changes

* http/2 and TLS 1.3 are the minimum baseline for transport.

* `GET /_matrix/key/v2/server` now returns an *optional* top-level boolean `m.linearized` field. If `true`, the
  server *only* supports Linearized Matrix and cannot handle full-mesh/DAG aspects. These servers are participants
  and sometimes hubs. The field is part of the signature.

* `PUT /_matrix/federation/v2/send/:txnId` is a new endpoint, modeled off of
  `PUT /_matrix/federation/v1/send/:txnId`. In short, the request body has the following changes:

  * `pdus` now accepts PDUs (events) and LPDUs (partial events).
  * `edus` remains optional (no changes).
  * `origin` doesn't exist/is removed.
  * `origin_server_ts` doesn't exist/is removed.

  Additionally, the response changes accordingly:

  * `pdus` is replaced by `failed_pdus`, retaining a similar structure. The `failed_pdus` object is keyed by
    failed event ID (LPDU event ID if it's not yet a PDU) with a an object value. The object value has the
    same schema as the `v1` endpoint: `error` as a human-readable string to denote the rejection reason.

    Note that events which are dropped or accepted do not appear in `failed_pdus`.

  All other behaviour is as detailed by the existing `PUT /_matrix/federation/v1/send/:txnId` endpoint.

  **Note**: This is implemented as `PUT /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/send/:txnId`
  as an unstable prefix.

* `GET /_matrix/federation/v2/event/:eventId` is a new endpoint, modeled off of
  `GET /_matrix/federation/v1/event/:eventId`. Instead of returning a single-PDU transaction, the endpoint
  simply returns the event at the top level, like in the Client-Server API.

  Additionally, `404 M_NOT_FOUND` semantics are more clearly defined. If the server can see the event, but
  not the contents, it is served redacted. If the server can't see the event or it doesn't exist, a 404 is
  returned.

  **Note**: This is implemented as `GET /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/event/:eventId`
  as an unstable prefix.

* `GET /_matrix/federation/v1/state/:roomId` has had its `404 M_NOT_FOUND` semantics clarified. If the server
  can see the returned events, but not their contents, they are served redacted. If the server can't see the
  room or the requested event/room doesn't exist, a 404 is returned.

* `GET /_matrix/federation/v1/state_ids/:roomId` has also had it's 404 semantics clarified to match `/state`
  above.

* `GET /_matrix/federation/v2/backfill/:roomId` is a new endpoint, modeled off of
  `GET /_matrix/federation/v1/backfill/:roomId`. Instead of returning a transaction containing PDUs, it returns
  just `{"pdus": [...]}`.

  It's also had its 404 semantics clarified (see `GET /state/:roomId` above), and returns an empty array if
  there are no previous events (ie: when requesting the `m.room.create` event). Additionally, the specification
  for Linearized Matrix only calls for a single `v` parameter, but servers are expected to handle multiple. Use
  caution if backfilling *from* a LM server because it'll likely use "the first one" rather than something
  sensible. Prefer to backfill from other DAG servers, or carefully consider your query.

  Further, `pdus` is ordered oldest to newest, and still includes `v`. In other words, `v` should be last.

  **Note**: This is implemented as `GET /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/backfill/:roomId`
  as an unstable prefix.

* `POST /_matrix/federation/v3/invite/:txnId` is a new endpoint, copying its request and response structures
  from `PUT /_matrix/federation/v2/invite/:roomId/:eventId`. Note the HTTP method change.

  `:txnId` can easily be an event ID.

  **Note**: This is implemented as `POST /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/invite/:txnId`
  as an unstable prefix.

* `POST /_matrix/federation/v3/send_join/:txnId` is a new endpoint, copying much of the behaviour from
  `PUT /_matrix/federation/v2/send_join/:roomId/:eventId`. Note the HTTP method change.

  `:txnId` can easily be an event ID.

  The request body will contain an LPDU instead of a PDU when coming from LM. The response body only consists
  of `state`, `auth_chain`, and `event`, though including other fields is okay too.

  Faster joins is not currently possible in LM, but will be in future. `omit_members` continues to default
  to false.

  **Note**: This is implemented as `POST /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/send_join/:txnId`
  as an unstable prefix.

* `POST /_matrix/federation/v3/send_leave/:txnId` is a new endpoint, copying much of the behaviour from
  `PUT /_matrix/federation/v2/send_leave/:roomId/:eventId`. Note the HTTP method change.

  `:txnId` can easily be an event ID.

  The request body will contain an LPDU instead of a PDU when coming from LM. The response body is still
  an empty object.

  **Note**: This is implemented as `POST /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/send_leave/:txnId`
  as an unstable prefix.

* `POST /_matrix/federation/v3/send_knock/:txnId` is a new endpoint, copying much of the behaviour from
  `PUT /_matrix/federation/v1/send_knock/:roomId/:eventId`. Note the HTTP method change.

  `:txnId` can easily be an event ID.

  The request body will contain an LPDU instead of a PDU when coming from LM. The response body instead
  contains `stripped_state`, retaining the same meaning as `knock_room_state`.

  **Note**: This is implemented as `POST /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/send_knock/:txnId`
  as an unstable prefix.

  **Note for future MSC**: This skips `v2`, and should be combined with the invite endpoint. make_knock
  should be part of a single make_membership endpoint.
* `GET /_matrix/federation/v1/user/:userId/device/:deviceId` is an entirely new endpoint, inspired by the
  existing device management and key query endpoints in Matrix already.

  **Note**: This is implemented as `POST /_matrix/federation/unstable/org.matrix.i-d.ralston-mimi-linearized-matrix.02/user/:userId/device/:deviceId`
  as an unstable prefix.

Some APIs are not implemented at all in LM:

* [3rd party invites](https://spec.matrix.org/v1.6/server-server-api/#third-party-invites)
* [`get_missing_events`](https://spec.matrix.org/v1.6/server-server-api/#post_matrixfederationv1get_missing_eventsroomid)
* [Public room directory](https://spec.matrix.org/v1.6/server-server-api/#public-room-directory)
* [Timestamp-to-event API](https://spec.matrix.org/v1.6/server-server-api/#get_matrixfederationv1timestamp_to_eventroomid)
* [Spaces](https://spec.matrix.org/v1.6/server-server-api/#spaces)
* [OpenID](https://spec.matrix.org/v1.6/server-server-api/#openid)
* `/_matrix/federation/v1/version` (maybe - TBD)

Expect LM servers to return error responses for these "unknown" endpoints.

## Grammar

* Room IDs must comply with [MSC1597's definition](https://github.com/matrix-org/matrix-spec-proposals/blob/rav/proposals/id_grammar/proposals/1597-id-grammar.md#room-ids-and-event-ids),
  with the following modification:
  ``` diff
  - This is only enforced for v2 rooms - servers and clients wishing to support v1 rooms should be more tolerant.
  + This is only enforced for room versions implied by the I-D - servers and clients wishing to support other room versions should be more tolerant.
  ```
* Device IDs have had their grammar clarified and are otherwise compatible.
* Server names are no longer allowed to be IPv4 or IPv6 addresses.
