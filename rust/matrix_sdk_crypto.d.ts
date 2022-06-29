/* tslint:disable */
/* eslint-disable */
/**
* An encryption algorithm to be used to encrypt messages sent to a
* room.
*/
export enum EncryptionAlgorithm {
/**
* Olm version 1 using Curve25519, AES-256, and SHA-256.
*/
  OlmV1Curve25519AesSha2,
/**
* Megolm version 1 using AES-256 and SHA-256.
*/
  MegolmV1AesSha2,
}
/**
* The verification state of the device that sent an event to us.
*/
export enum VerificationState {
/**
* The device is trusted.
*/
  Trusted,
/**
* The device is not trusted.
*/
  Untrusted,
/**
* The device is not known to us.
*/
  UnknownDevice,
}
/**
* Who can see a room's history.
*/
export enum HistoryVisibility {
/**
* Previous events are accessible to newly joined members from
* the point they were invited onwards.
*
* Events stop being accessible when the member's state changes
* to something other than *invite* or *join*.
*/
  Invited,
/**
* Previous events are accessible to newly joined members from
* the point they joined the room onwards.
*
* Events stop being accessible when the member's state changes
* to something other than *join*.
*/
  Joined,
/**
* Previous events are always accessible to newly joined members.
*
* All events in the room are accessible, even those sent when
* the member was not a part of the room.
*/
  Shared,
/**
* All events while this is the `HistoryVisibility` value may be
* shared by any participating homeserver with anyone, regardless
* of whether they have ever joined the room.
*/
  WorldReadable,
}
/**
* Represent the type of a request.
*/
export enum RequestType {
/**
* Represents a `KeysUploadRequest`.
*/
  KeysUpload,
/**
* Represents a `KeysQueryRequest`.
*/
  KeysQuery,
/**
* Represents a `KeysClaimRequest`.
*/
  KeysClaim,
/**
* Represents a `ToDeviceRequest`.
*/
  ToDevice,
/**
* Represents a `SignatureUploadRequest`.
*/
  SignatureUpload,
/**
* Represents a `RoomMessageRequest`.
*/
  RoomMessage,
/**
* Represents a `KeysBackupRequest`.
*/
  KeysBackup,
}
/**
* A Curve25519 public key.
*/
export class Curve25519PublicKey {
  free(): void;
/**
* Serialize an Curve25519 public key to an unpadded base64
* representation.
* @returns {string}
*/
  toBase64(): string;
/**
* The number of bytes a Curve25519 public key has.
* @returns {number}
*/
  readonly length: number;
}
/**
* A decrypted room event.
*/
export class DecryptedRoomEvent {
  free(): void;
/**
* The JSON-encoded decrypted event.
*/
  readonly event: void;
/**
* Chain of Curve25519 keys through which this session was
* forwarded, via `m.forwarded_room_key` events.
* @returns {Array<any> | undefined}
*/
  readonly forwardingCurve25519KeyChain: Array<any> | undefined;
/**
* The user ID of the event sender, note this is untrusted data
* unless the `verification_state` is as well trusted.
* @returns {UserId | undefined}
*/
  readonly sender: UserId | undefined;
/**
* The signing Ed25519 key that have created the megolm key that
* was used to decrypt this session.
* @returns {string | undefined}
*/
  readonly senderClaimedEd25519Key: string | undefined;
/**
* The Curve25519 key of the device that created the megolm
* decryption key originally.
* @returns {string | undefined}
*/
  readonly senderCurve25519Key: string | undefined;
/**
* The device ID of the device that sent us the event, note this
* is untrusted data unless `verification_state` is as well
* trusted.
* @returns {DeviceId | undefined}
*/
  readonly senderDevice: DeviceId | undefined;
/**
* The verification state of the device that sent us the event,
* note this is the state of the device at the time of
* decryption. It may change in the future if a device gets
* verified or deleted.
* @returns {number | undefined}
*/
  readonly verificationState: number | undefined;
}
/**
* A Matrix key ID.
*
* Device identifiers in Matrix are completely opaque character
* sequences. This type is provided simply for its semantic value.
*/
export class DeviceId {
  free(): void;
/**
* Create a new `DeviceId`.
* @param {string} id
*/
  constructor(id: string);
/**
* Return the device ID as a string.
* @returns {string}
*/
  toString(): string;
}
/**
* Information on E2E device updates.
*/
export class DeviceLists {
  free(): void;
/**
* Create an empty `DeviceLists`.
*
* `changed` and `left` must be an array of `UserId`.
* @param {Array<any> | undefined} changed
* @param {Array<any> | undefined} left
*/
  constructor(changed?: Array<any>, left?: Array<any>);
/**
* Returns true if there are no device list updates.
* @returns {boolean}
*/
  isEmpty(): boolean;
/**
* List of users who have updated their device identity keys or
* who now share an encrypted room with the client since the
* previous sync
* @returns {Array<any>}
*/
  readonly changed: Array<any>;
/**
* List of users who no longer share encrypted rooms since the
* previous sync response.
* @returns {Array<any>}
*/
  readonly left: Array<any>;
}
/**
* An Ed25519 public key, used to verify digital signatures.
*/
export class Ed25519PublicKey {
  free(): void;
/**
* Serialize an Ed25519 public key to an unpadded base64
* representation.
* @returns {string}
*/
  toBase64(): string;
/**
* The number of bytes an Ed25519 public key has.
* @returns {number}
*/
  readonly length: number;
}
/**
* Settings for an encrypted room.
*
* This determines the algorithm and rotation periods of a group
* session.
*/
export class EncryptionSettings {
  free(): void;
/**
* Create a new `EncryptionSettings` with default values.
*/
  constructor();
/**
* The encryption algorithm that should be used in the room.
*/
  algorithm: number;
/**
* The history visibility of the room when the session was
* created.
*/
  historyVisibility: number;
/**
* How long the session should be used before changing it,
* expressed in microseconds.
*/
  rotationPeriod: BigInt;
/**
* How many messages should be sent before changing the session.
*/
  rotationPeriodMessages: BigInt;
}
/**
* Struct holding the two public identity keys of an account.
*/
export class IdentityKeys {
  free(): void;
/**
* The Curve25519 public key, used for establish shared secrets.
*/
  curve25519: Curve25519PublicKey;
/**
* The Ed25519 public key, used for signing.
*/
  ed25519: Ed25519PublicKey;
}
/**
* A request that will back up a batch of room keys to the server
* ([specification]).
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3room_keyskeys
*/
export class KeysBackupRequest {
  free(): void;
/**
* Create a new `KeysBackupRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"rooms": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* Data for a request to the `/keys/claim` API endpoint
* ([specification]).
*
* Claims one-time keys that can be used to establish 1-to-1 E2EE
* sessions.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysclaim
*/
export class KeysClaimRequest {
  free(): void;
/**
* Create a new `KeysClaimRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"timeout": …, "one_time_keys": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* Data for a request to the `/keys/query` API endpoint
* ([specification]).
*
* Returns the current devices and identity keys for the given users.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysquery
*/
export class KeysQueryRequest {
  free(): void;
/**
* Create a new `KeysQueryRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"timeout": …, "device_keys": …, "token": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* Data for a request to the `/keys/upload` API endpoint
* ([specification]).
*
* Publishes end-to-end encryption keys for the device.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysupload
*/
export class KeysUploadRequest {
  free(): void;
/**
* Create a new `KeysUploadRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"device_keys": …, "one_time_keys": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* State machine implementation of the Olm/Megolm encryption protocol
* used for Matrix end to end encryption.
*/
export class OlmMachine {
  free(): void;
/**
* Create a new memory based `OlmMachine`.
*
* The created machine will keep the encryption keys only in
* memory and once the objects is dropped, the keys will be lost.
*
* `user_id` represents the unique ID of the user that owns this
* machine. `device_id` represents the unique ID of the device
* that owns this machine.
* @param {UserId} user_id
* @param {DeviceId} device_id
*/
  constructor(user_id: UserId, device_id: DeviceId);
/**
* Get all the tracked users of our own device.
*
* Returns a `Set<UserId>`.
* @returns {Set<any>}
*/
  trackedUsers(): Set<any>;
/**
* Update the tracked users.
*
* `users` is an iterator over user IDs that should be marked for
* tracking.
*
* This will mark users that weren't seen before for a key query
* and tracking.
*
* If the user is already known to the Olm machine, it will not
* be considered for a key query.
* @param {Array<any>} users
* @returns {Promise<any>}
*/
  updateTrackedUsers(users: Array<any>): Promise<any>;
/**
* Handle to-device events and one-time key counts from a sync
* response.
*
* This will decrypt and handle to-device events returning the
* decrypted versions of them.
*
* To decrypt an event from the room timeline call
* `decrypt_room_event`.
* @param {string} to_device_events
* @param {DeviceLists} changed_devices
* @param {Map<any, any>} one_time_key_counts
* @param {Set<any>} unused_fallback_keys
* @returns {Promise<any>}
*/
  receiveSyncChanges(to_device_events: string, changed_devices: DeviceLists, one_time_key_counts: Map<any, any>, unused_fallback_keys: Set<any>): Promise<any>;
/**
* Get the outgoing requests that need to be sent out.
*
* This returns a list of `JsValue` to represent either:
*   * `KeysUploadRequest`,
*   * `KeysQueryRequest`,
*   * `KeysClaimRequest`,
*   * `ToDeviceRequest`,
*   * `SignatureUploadRequest`,
*   * `RoomMessageRequest` or
*   * `KeysBackupRequest`.
*
* Those requests need to be sent out to the server and the
* responses need to be passed back to the state machine using
* `mark_request_as_sent`.
* @returns {Promise<any>}
*/
  outgoingRequests(): Promise<any>;
/**
* Mark the request with the given request ID as sent (see
* `outgoing_requests`).
*
* Arguments are:
*
* * `request_id` represents the unique ID of the request that was sent
*   out. This is needed to couple the response with the now sent out
*   request.
* * `response_type` represents the type of the request that was sent out.
* * `response` represents the response that was received from the server
*   after the outgoing request was sent out.
* @param {string} request_id
* @param {number} request_type
* @param {string} response
* @returns {Promise<any>}
*/
  markRequestAsSent(request_id: string, request_type: number, response: string): Promise<any>;
/**
* Encrypt a room message for the given room.
*
* Beware that a room key needs to be shared before this
* method can be called using the `share_room_key` method.
*
* `room_id` is the ID of the room for which the message should
* be encrypted. `event_type` is the type of the event. `content`
* is the plaintext content of the message that should be
* encrypted.
*
* # Panics
*
* Panics if a group session for the given room wasn't shared
* beforehand.
* @param {RoomId} room_id
* @param {string} event_type
* @param {string} content
* @returns {Promise<any>}
*/
  encryptRoomEvent(room_id: RoomId, event_type: string, content: string): Promise<any>;
/**
* Decrypt an event from a room timeline.
*
* # Arguments
*
* * `event`, the event that should be decrypted.
* * `room_id`, the ID of the room where the event was sent to.
* @param {string} event
* @param {RoomId} room_id
* @returns {Promise<any>}
*/
  decryptRoomEvent(event: string, room_id: RoomId): Promise<any>;
/**
* Invalidate the currently active outbound group session for the
* given room.
*
* Returns true if a session was invalidated, false if there was
* no session to invalidate.
* @param {RoomId} room_id
* @returns {Promise<any>}
*/
  invalidateGroupSession(room_id: RoomId): Promise<any>;
/**
* Get to-device requests to share a room key with users in a room.
*
* `room_id` is the room ID. `users` is an array of `UserId`
* objects. `encryption_settings` are an `EncryptionSettings`
* object.
* @param {RoomId} room_id
* @param {Array<any>} users
* @param {EncryptionSettings} encryption_settings
* @returns {Promise<any>}
*/
  shareRoomKey(room_id: RoomId, users: Array<any>, encryption_settings: EncryptionSettings): Promise<any>;
/**
* Get the a key claiming request for the user/device pairs that
* we are missing Olm sessions for.
*
* Returns `NULL` if no key claiming request needs to be sent
* out, otherwise it returns an `Array` where the first key is
* the transaction ID as a string, and the second key is the keys
* claim request serialized to JSON.
*
* Sessions need to be established between devices so group
* sessions for a room can be shared with them.
*
* This should be called every time a group session needs to be
* shared as well as between sync calls. After a sync some
* devices may request room keys without us having a valid Olm
* session with them, making it impossible to server the room key
* request, thus it’s necessary to check for missing sessions
* between sync as well.
*
* Note: Care should be taken that only one such request at a
* time is in flight, e.g. using a lock.
*
* The response of a successful key claiming requests needs to be
* passed to the `OlmMachine` with the `mark_request_as_sent`.
*
* `users` represents the list of users that we should check if
* we lack a session with one of their devices. This can be an
* empty iterator when calling this method between sync requests.
* @param {Array<any>} users
* @returns {Promise<any>}
*/
  getMissingSessions(users: Array<any>): Promise<any>;
/**
* The unique device ID that identifies this `OlmMachine`.
* @returns {DeviceId}
*/
  readonly deviceId: DeviceId;
/**
* Get the display name of our own device.
* @returns {Promise<any>}
*/
  readonly displayName: Promise<any>;
/**
* Get the public parts of our Olm identity keys.
* @returns {IdentityKeys}
*/
  readonly identityKeys: IdentityKeys;
/**
* The unique user ID that owns this `OlmMachine` instance.
* @returns {UserId}
*/
  readonly userId: UserId;
}
/**
* A Matrix [room ID].
*
* [room ID]: https://spec.matrix.org/v1.2/appendices/#room-ids-and-event-ids
*/
export class RoomId {
  free(): void;
/**
* Parse/validate and create a new `RoomId`.
* @param {string} id
*/
  constructor(id: string);
/**
* Return the room ID as a string.
* @returns {string}
*/
  toString(): string;
/**
* Returns the user's localpart.
* @returns {string}
*/
  readonly localpart: string;
/**
* Returns the server name of the room ID.
* @returns {ServerName}
*/
  readonly serverName: ServerName;
}
/**
* A customized owned request type for sending out room messages
* ([specification]).
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
*/
export class RoomMessageRequest {
  free(): void;
/**
* Create a new `RoomMessageRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"room_id": …, "txn_id": …, "content": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* A Matrix-spec compliant [server name].
*
* It consists of a host and an optional port (separated by a colon if
* present).
*
* [server name]: https://spec.matrix.org/v1.2/appendices/#server-name
*/
export class ServerName {
  free(): void;
/**
* Parse/validate and create a new `ServerName`.
* @param {string} name
*/
  constructor(name: string);
/**
* Returns true if and only if the server name is an IPv4 or IPv6
* address.
* @returns {boolean}
*/
  isIpLiteral(): boolean;
/**
* Returns the host of the server name.
*
* That is: Return the part of the server before `:<port>` or the
* full server name if there is no port.
* @returns {string}
*/
  readonly host: string;
/**
* Returns the port of the server name if any.
* @returns {number | undefined}
*/
  readonly port: number | undefined;
}
/**
* Data for a request to the `/keys/signatures/upload` API endpoint
* ([specification]).
*
* Publishes cross-signing signatures for the user.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keyssignaturesupload
*/
export class SignatureUploadRequest {
  free(): void;
/**
* Create a new `SignatureUploadRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"signed_keys": …, "txn_id": …, "messages": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* Data for a request to the `/sendToDevice` API endpoint
* ([specification]).
*
* Send an event to a single device or to a group of devices.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3sendtodeviceeventtypetxnid
*/
export class ToDeviceRequest {
  free(): void;
/**
* Create a new `ToDeviceRequest`.
* @param {string} id
* @param {string} body
*/
  constructor(id: string, body: string);
/**
* A JSON-encoded object of form:
*
* ```json
* {"event_type": …, "txn_id": …, "messages": …}
* ```
*/
  readonly body: void;
/**
* The request ID.
*/
  readonly id: void;
/**
* Get its request type.
* @returns {number}
*/
  readonly type: number;
}
/**
* A Matrix [user ID].
*
* [user ID]: https://spec.matrix.org/v1.2/appendices/#user-identifiers
*/
export class UserId {
  free(): void;
/**
* Parse/validate and create a new `UserId`.
* @param {string} id
*/
  constructor(id: string);
/**
* Whether this user ID is a historical one.
*
* A historical user ID is one that doesn't conform to the latest
* specification of the user ID grammar but is still accepted
* because it was previously allowed.
* @returns {boolean}
*/
  isHistorical(): boolean;
/**
* Return the user ID as a string.
* @returns {string}
*/
  toString(): string;
/**
* Returns the user's localpart.
* @returns {string}
*/
  readonly localpart: string;
/**
* Returns the server name of the user ID.
* @returns {ServerName}
*/
  readonly serverName: ServerName;
}
