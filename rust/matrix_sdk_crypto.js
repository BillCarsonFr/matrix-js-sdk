let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm;
const { TextEncoder, TextDecoder } = require(`util`);

const heap = new Array(32).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

let WASM_VECTOR_LEN = 0;

let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

let cachegetFloat64Memory0 = null;
function getFloat64Memory0() {
    if (cachegetFloat64Memory0 === null || cachegetFloat64Memory0.buffer !== wasm.memory.buffer) {
        cachegetFloat64Memory0 = new Float64Array(wasm.memory.buffer);
    }
    return cachegetFloat64Memory0;
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {
        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            if (--state.cnt === 0) {
                wasm.__wbindgen_export_2.get(state.dtor)(a, state.b);

            } else {
                state.a = a;
            }
        }
    };
    real.original = state;

    return real;
}
function __wbg_adapter_26(arg0, arg1, arg2) {
    wasm._dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h7c68bc601282a844(arg0, arg1, addHeapObject(arg2));
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
function __wbg_adapter_105(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures__invoke2_mut__he9a9b53529379e5e(arg0, arg1, addHeapObject(arg2), addHeapObject(arg3));
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}

let stack_pointer = 32;

function addBorrowedObject(obj) {
    if (stack_pointer == 1) throw new Error('out of js stack');
    heap[--stack_pointer] = obj;
    return stack_pointer;
}

const u32CvtShim = new Uint32Array(2);

const uint64CvtShim = new BigUint64Array(u32CvtShim.buffer);
/**
* An encryption algorithm to be used to encrypt messages sent to a
* room.
*/
module.exports.EncryptionAlgorithm = Object.freeze({
/**
* Olm version 1 using Curve25519, AES-256, and SHA-256.
*/
OlmV1Curve25519AesSha2:0,"0":"OlmV1Curve25519AesSha2",
/**
* Megolm version 1 using AES-256 and SHA-256.
*/
MegolmV1AesSha2:1,"1":"MegolmV1AesSha2", });
/**
* The verification state of the device that sent an event to us.
*/
module.exports.VerificationState = Object.freeze({
/**
* The device is trusted.
*/
Trusted:0,"0":"Trusted",
/**
* The device is not trusted.
*/
Untrusted:1,"1":"Untrusted",
/**
* The device is not known to us.
*/
UnknownDevice:2,"2":"UnknownDevice", });
/**
* Who can see a room's history.
*/
module.exports.HistoryVisibility = Object.freeze({
/**
* Previous events are accessible to newly joined members from
* the point they were invited onwards.
*
* Events stop being accessible when the member's state changes
* to something other than *invite* or *join*.
*/
Invited:0,"0":"Invited",
/**
* Previous events are accessible to newly joined members from
* the point they joined the room onwards.
*
* Events stop being accessible when the member's state changes
* to something other than *join*.
*/
Joined:1,"1":"Joined",
/**
* Previous events are always accessible to newly joined members.
*
* All events in the room are accessible, even those sent when
* the member was not a part of the room.
*/
Shared:2,"2":"Shared",
/**
* All events while this is the `HistoryVisibility` value may be
* shared by any participating homeserver with anyone, regardless
* of whether they have ever joined the room.
*/
WorldReadable:3,"3":"WorldReadable", });
/**
* Represent the type of a request.
*/
module.exports.RequestType = Object.freeze({
/**
* Represents a `KeysUploadRequest`.
*/
KeysUpload:0,"0":"KeysUpload",
/**
* Represents a `KeysQueryRequest`.
*/
KeysQuery:1,"1":"KeysQuery",
/**
* Represents a `KeysClaimRequest`.
*/
KeysClaim:2,"2":"KeysClaim",
/**
* Represents a `ToDeviceRequest`.
*/
ToDevice:3,"3":"ToDevice",
/**
* Represents a `SignatureUploadRequest`.
*/
SignatureUpload:4,"4":"SignatureUpload",
/**
* Represents a `RoomMessageRequest`.
*/
RoomMessage:5,"5":"RoomMessage",
/**
* Represents a `KeysBackupRequest`.
*/
KeysBackup:6,"6":"KeysBackup", });
/**
* A Curve25519 public key.
*/
class Curve25519PublicKey {

    static __wrap(ptr) {
        const obj = Object.create(Curve25519PublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_curve25519publickey_free(ptr);
    }
    /**
    * The number of bytes a Curve25519 public key has.
    * @returns {number}
    */
    get length() {
        const ret = wasm.curve25519publickey_length(this.ptr);
        return ret >>> 0;
    }
    /**
    * Serialize an Curve25519 public key to an unpadded base64
    * representation.
    * @returns {string}
    */
    toBase64() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.curve25519publickey_toBase64(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
module.exports.Curve25519PublicKey = Curve25519PublicKey;
/**
* A decrypted room event.
*/
class DecryptedRoomEvent {

    static __wrap(ptr) {
        const obj = Object.create(DecryptedRoomEvent.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_decryptedroomevent_free(ptr);
    }
    /**
    * The JSON-encoded decrypted event.
    */
    get event() {
        const ret = wasm.__wbg_get_decryptedroomevent_event(this.ptr);
        return takeObject(ret);
    }
    /**
    * The user ID of the event sender, note this is untrusted data
    * unless the `verification_state` is as well trusted.
    * @returns {UserId | undefined}
    */
    get sender() {
        const ret = wasm.decryptedroomevent_sender(this.ptr);
        return ret === 0 ? undefined : UserId.__wrap(ret);
    }
    /**
    * The device ID of the device that sent us the event, note this
    * is untrusted data unless `verification_state` is as well
    * trusted.
    * @returns {DeviceId | undefined}
    */
    get senderDevice() {
        const ret = wasm.decryptedroomevent_senderDevice(this.ptr);
        return ret === 0 ? undefined : DeviceId.__wrap(ret);
    }
    /**
    * The Curve25519 key of the device that created the megolm
    * decryption key originally.
    * @returns {string | undefined}
    */
    get senderCurve25519Key() {
        const ret = wasm.decryptedroomevent_senderCurve25519Key(this.ptr);
        return takeObject(ret);
    }
    /**
    * The signing Ed25519 key that have created the megolm key that
    * was used to decrypt this session.
    * @returns {string | undefined}
    */
    get senderClaimedEd25519Key() {
        const ret = wasm.decryptedroomevent_senderClaimedEd25519Key(this.ptr);
        return takeObject(ret);
    }
    /**
    * Chain of Curve25519 keys through which this session was
    * forwarded, via `m.forwarded_room_key` events.
    * @returns {Array<any> | undefined}
    */
    get forwardingCurve25519KeyChain() {
        const ret = wasm.decryptedroomevent_forwardingCurve25519KeyChain(this.ptr);
        return takeObject(ret);
    }
    /**
    * The verification state of the device that sent us the event,
    * note this is the state of the device at the time of
    * decryption. It may change in the future if a device gets
    * verified or deleted.
    * @returns {number | undefined}
    */
    get verificationState() {
        const ret = wasm.decryptedroomevent_verificationState(this.ptr);
        return ret === 3 ? undefined : ret;
    }
}
module.exports.DecryptedRoomEvent = DecryptedRoomEvent;
/**
* A Matrix key ID.
*
* Device identifiers in Matrix are completely opaque character
* sequences. This type is provided simply for its semantic value.
*/
class DeviceId {

    static __wrap(ptr) {
        const obj = Object.create(DeviceId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_deviceid_free(ptr);
    }
    /**
    * Create a new `DeviceId`.
    * @param {string} id
    */
    constructor(id) {
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.deviceid_new(ptr0, len0);
        return DeviceId.__wrap(ret);
    }
    /**
    * Return the device ID as a string.
    * @returns {string}
    */
    toString() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.deviceid_toString(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
module.exports.DeviceId = DeviceId;
/**
* Information on E2E device updates.
*/
class DeviceLists {

    static __wrap(ptr) {
        const obj = Object.create(DeviceLists.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_devicelists_free(ptr);
    }
    /**
    * Create an empty `DeviceLists`.
    *
    * `changed` and `left` must be an array of `UserId`.
    * @param {Array<any> | undefined} changed
    * @param {Array<any> | undefined} left
    */
    constructor(changed, left) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.devicelists_new(retptr, isLikeNone(changed) ? 0 : addHeapObject(changed), isLikeNone(left) ? 0 : addHeapObject(left));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return DeviceLists.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Returns true if there are no device list updates.
    * @returns {boolean}
    */
    isEmpty() {
        const ret = wasm.devicelists_isEmpty(this.ptr);
        return ret !== 0;
    }
    /**
    * List of users who have updated their device identity keys or
    * who now share an encrypted room with the client since the
    * previous sync
    * @returns {Array<any>}
    */
    get changed() {
        const ret = wasm.devicelists_changed(this.ptr);
        return takeObject(ret);
    }
    /**
    * List of users who no longer share encrypted rooms since the
    * previous sync response.
    * @returns {Array<any>}
    */
    get left() {
        const ret = wasm.devicelists_left(this.ptr);
        return takeObject(ret);
    }
}
module.exports.DeviceLists = DeviceLists;
/**
* An Ed25519 public key, used to verify digital signatures.
*/
class Ed25519PublicKey {

    static __wrap(ptr) {
        const obj = Object.create(Ed25519PublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ed25519publickey_free(ptr);
    }
    /**
    * The number of bytes an Ed25519 public key has.
    * @returns {number}
    */
    get length() {
        const ret = wasm.ed25519publickey_length(this.ptr);
        return ret >>> 0;
    }
    /**
    * Serialize an Ed25519 public key to an unpadded base64
    * representation.
    * @returns {string}
    */
    toBase64() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.ed25519publickey_toBase64(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
module.exports.Ed25519PublicKey = Ed25519PublicKey;
/**
* Settings for an encrypted room.
*
* This determines the algorithm and rotation periods of a group
* session.
*/
class EncryptionSettings {

    static __wrap(ptr) {
        const obj = Object.create(EncryptionSettings.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptionsettings_free(ptr);
    }
    /**
    * The encryption algorithm that should be used in the room.
    */
    get algorithm() {
        const ret = wasm.__wbg_get_encryptionsettings_algorithm(this.ptr);
        return ret >>> 0;
    }
    /**
    * The encryption algorithm that should be used in the room.
    * @param {number} arg0
    */
    set algorithm(arg0) {
        wasm.__wbg_set_encryptionsettings_algorithm(this.ptr, arg0);
    }
    /**
    * How long the session should be used before changing it,
    * expressed in microseconds.
    */
    get rotationPeriod() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_encryptionsettings_rotationPeriod(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            u32CvtShim[0] = r0;
            u32CvtShim[1] = r1;
            const n0 = uint64CvtShim[0];
            return n0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * How long the session should be used before changing it,
    * expressed in microseconds.
    * @param {BigInt} arg0
    */
    set rotationPeriod(arg0) {
        uint64CvtShim[0] = arg0;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        wasm.__wbg_set_encryptionsettings_rotationPeriod(this.ptr, low0, high0);
    }
    /**
    * How many messages should be sent before changing the session.
    */
    get rotationPeriodMessages() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_encryptionsettings_rotationPeriodMessages(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            u32CvtShim[0] = r0;
            u32CvtShim[1] = r1;
            const n0 = uint64CvtShim[0];
            return n0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * How many messages should be sent before changing the session.
    * @param {BigInt} arg0
    */
    set rotationPeriodMessages(arg0) {
        uint64CvtShim[0] = arg0;
        const low0 = u32CvtShim[0];
        const high0 = u32CvtShim[1];
        wasm.__wbg_set_encryptionsettings_rotationPeriodMessages(this.ptr, low0, high0);
    }
    /**
    * The history visibility of the room when the session was
    * created.
    */
    get historyVisibility() {
        const ret = wasm.__wbg_get_encryptionsettings_historyVisibility(this.ptr);
        return ret >>> 0;
    }
    /**
    * The history visibility of the room when the session was
    * created.
    * @param {number} arg0
    */
    set historyVisibility(arg0) {
        wasm.__wbg_set_encryptionsettings_historyVisibility(this.ptr, arg0);
    }
    /**
    * Create a new `EncryptionSettings` with default values.
    */
    constructor() {
        const ret = wasm.encryptionsettings_new();
        return EncryptionSettings.__wrap(ret);
    }
}
module.exports.EncryptionSettings = EncryptionSettings;
/**
* Struct holding the two public identity keys of an account.
*/
class IdentityKeys {

    static __wrap(ptr) {
        const obj = Object.create(IdentityKeys.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_identitykeys_free(ptr);
    }
    /**
    * The Ed25519 public key, used for signing.
    */
    get ed25519() {
        const ret = wasm.__wbg_get_identitykeys_ed25519(this.ptr);
        return Ed25519PublicKey.__wrap(ret);
    }
    /**
    * The Ed25519 public key, used for signing.
    * @param {Ed25519PublicKey} arg0
    */
    set ed25519(arg0) {
        _assertClass(arg0, Ed25519PublicKey);
        var ptr0 = arg0.ptr;
        arg0.ptr = 0;
        wasm.__wbg_set_identitykeys_ed25519(this.ptr, ptr0);
    }
    /**
    * The Curve25519 public key, used for establish shared secrets.
    */
    get curve25519() {
        const ret = wasm.__wbg_get_identitykeys_curve25519(this.ptr);
        return Curve25519PublicKey.__wrap(ret);
    }
    /**
    * The Curve25519 public key, used for establish shared secrets.
    * @param {Curve25519PublicKey} arg0
    */
    set curve25519(arg0) {
        _assertClass(arg0, Curve25519PublicKey);
        var ptr0 = arg0.ptr;
        arg0.ptr = 0;
        wasm.__wbg_set_identitykeys_curve25519(this.ptr, ptr0);
    }
}
module.exports.IdentityKeys = IdentityKeys;
/**
* A request that will back up a batch of room keys to the server
* ([specification]).
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3room_keyskeys
*/
class KeysBackupRequest {

    static __wrap(ptr) {
        const obj = Object.create(KeysBackupRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keysbackuprequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_keysbackuprequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"rooms": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_keysbackuprequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `KeysBackupRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.keysbackuprequest_new(addHeapObject(id), addHeapObject(body));
        return KeysBackupRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.keysbackuprequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.KeysBackupRequest = KeysBackupRequest;
/**
* Data for a request to the `/keys/claim` API endpoint
* ([specification]).
*
* Claims one-time keys that can be used to establish 1-to-1 E2EE
* sessions.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysclaim
*/
class KeysClaimRequest {

    static __wrap(ptr) {
        const obj = Object.create(KeysClaimRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keysclaimrequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_keysclaimrequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"timeout": …, "one_time_keys": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_keysclaimrequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `KeysClaimRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.keysclaimrequest_new(addHeapObject(id), addHeapObject(body));
        return KeysClaimRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.keysclaimrequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.KeysClaimRequest = KeysClaimRequest;
/**
* Data for a request to the `/keys/query` API endpoint
* ([specification]).
*
* Returns the current devices and identity keys for the given users.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysquery
*/
class KeysQueryRequest {

    static __wrap(ptr) {
        const obj = Object.create(KeysQueryRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keysqueryrequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_keysqueryrequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"timeout": …, "device_keys": …, "token": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_keysqueryrequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `KeysQueryRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.keysqueryrequest_new(addHeapObject(id), addHeapObject(body));
        return KeysQueryRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.keysqueryrequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.KeysQueryRequest = KeysQueryRequest;
/**
* Data for a request to the `/keys/upload` API endpoint
* ([specification]).
*
* Publishes end-to-end encryption keys for the device.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keysupload
*/
class KeysUploadRequest {

    static __wrap(ptr) {
        const obj = Object.create(KeysUploadRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keysuploadrequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_keysuploadrequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"device_keys": …, "one_time_keys": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_keysuploadrequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `KeysUploadRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.keysuploadrequest_new(addHeapObject(id), addHeapObject(body));
        return KeysUploadRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.keysuploadrequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.KeysUploadRequest = KeysUploadRequest;
/**
* State machine implementation of the Olm/Megolm encryption protocol
* used for Matrix end to end encryption.
*/
class OlmMachine {

    static __wrap(ptr) {
        const obj = Object.create(OlmMachine.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_olmmachine_free(ptr);
    }
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
    constructor(user_id, device_id) {
        _assertClass(user_id, UserId);
        _assertClass(device_id, DeviceId);
        const ret = wasm.olmmachine_new(user_id.ptr, device_id.ptr);
        return takeObject(ret);
    }
    /**
    * The unique user ID that owns this `OlmMachine` instance.
    * @returns {UserId}
    */
    get userId() {
        const ret = wasm.olmmachine_userId(this.ptr);
        return UserId.__wrap(ret);
    }
    /**
    * The unique device ID that identifies this `OlmMachine`.
    * @returns {DeviceId}
    */
    get deviceId() {
        const ret = wasm.olmmachine_deviceId(this.ptr);
        return DeviceId.__wrap(ret);
    }
    /**
    * Get the public parts of our Olm identity keys.
    * @returns {IdentityKeys}
    */
    get identityKeys() {
        const ret = wasm.olmmachine_identityKeys(this.ptr);
        return IdentityKeys.__wrap(ret);
    }
    /**
    * Get the display name of our own device.
    * @returns {Promise<any>}
    */
    get displayName() {
        const ret = wasm.olmmachine_displayName(this.ptr);
        return takeObject(ret);
    }
    /**
    * Get all the tracked users of our own device.
    *
    * Returns a `Set<UserId>`.
    * @returns {Set<any>}
    */
    trackedUsers() {
        const ret = wasm.olmmachine_trackedUsers(this.ptr);
        return takeObject(ret);
    }
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
    updateTrackedUsers(users) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.olmmachine_updateTrackedUsers(retptr, this.ptr, addBorrowedObject(users));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
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
    receiveSyncChanges(to_device_events, changed_devices, one_time_key_counts, unused_fallback_keys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(to_device_events, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(changed_devices, DeviceLists);
            wasm.olmmachine_receiveSyncChanges(retptr, this.ptr, ptr0, len0, changed_devices.ptr, addBorrowedObject(one_time_key_counts), addBorrowedObject(unused_fallback_keys));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
            heap[stack_pointer++] = undefined;
        }
    }
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
    outgoingRequests() {
        const ret = wasm.olmmachine_outgoingRequests(this.ptr);
        return takeObject(ret);
    }
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
    markRequestAsSent(request_id, request_type, response) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(request_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(response, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            wasm.olmmachine_markRequestAsSent(retptr, this.ptr, ptr0, len0, request_type, ptr1, len1);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
    encryptRoomEvent(room_id, event_type, content) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(room_id, RoomId);
            const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(content, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            wasm.olmmachine_encryptRoomEvent(retptr, this.ptr, room_id.ptr, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
    decryptRoomEvent(event, room_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(event, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(room_id, RoomId);
            wasm.olmmachine_decryptRoomEvent(retptr, this.ptr, ptr0, len0, room_id.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Invalidate the currently active outbound group session for the
    * given room.
    *
    * Returns true if a session was invalidated, false if there was
    * no session to invalidate.
    * @param {RoomId} room_id
    * @returns {Promise<any>}
    */
    invalidateGroupSession(room_id) {
        _assertClass(room_id, RoomId);
        const ret = wasm.olmmachine_invalidateGroupSession(this.ptr, room_id.ptr);
        return takeObject(ret);
    }
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
    shareRoomKey(room_id, users, encryption_settings) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(room_id, RoomId);
            _assertClass(encryption_settings, EncryptionSettings);
            wasm.olmmachine_shareRoomKey(retptr, this.ptr, room_id.ptr, addBorrowedObject(users), encryption_settings.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
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
    getMissingSessions(users) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.olmmachine_getMissingSessions(retptr, this.ptr, addBorrowedObject(users));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
}
module.exports.OlmMachine = OlmMachine;
/**
* A Matrix [room ID].
*
* [room ID]: https://spec.matrix.org/v1.2/appendices/#room-ids-and-event-ids
*/
class RoomId {

    static __wrap(ptr) {
        const obj = Object.create(RoomId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_roomid_free(ptr);
    }
    /**
    * Parse/validate and create a new `RoomId`.
    * @param {string} id
    */
    constructor(id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.roomid_new(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return RoomId.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Returns the user's localpart.
    * @returns {string}
    */
    get localpart() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.roomid_localpart(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Returns the server name of the room ID.
    * @returns {ServerName}
    */
    get serverName() {
        const ret = wasm.roomid_serverName(this.ptr);
        return ServerName.__wrap(ret);
    }
    /**
    * Return the room ID as a string.
    * @returns {string}
    */
    toString() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.roomid_toString(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
module.exports.RoomId = RoomId;
/**
* A customized owned request type for sending out room messages
* ([specification]).
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
*/
class RoomMessageRequest {

    static __wrap(ptr) {
        const obj = Object.create(RoomMessageRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_roommessagerequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_roommessagerequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"room_id": …, "txn_id": …, "content": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_roommessagerequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `RoomMessageRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.roommessagerequest_new(addHeapObject(id), addHeapObject(body));
        return RoomMessageRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.roommessagerequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.RoomMessageRequest = RoomMessageRequest;
/**
* A Matrix-spec compliant [server name].
*
* It consists of a host and an optional port (separated by a colon if
* present).
*
* [server name]: https://spec.matrix.org/v1.2/appendices/#server-name
*/
class ServerName {

    static __wrap(ptr) {
        const obj = Object.create(ServerName.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_servername_free(ptr);
    }
    /**
    * Parse/validate and create a new `ServerName`.
    * @param {string} name
    */
    constructor(name) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.servername_new(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return ServerName.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Returns the host of the server name.
    *
    * That is: Return the part of the server before `:<port>` or the
    * full server name if there is no port.
    * @returns {string}
    */
    get host() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.servername_host(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Returns the port of the server name if any.
    * @returns {number | undefined}
    */
    get port() {
        const ret = wasm.servername_port(this.ptr);
        return ret === 0xFFFFFF ? undefined : ret;
    }
    /**
    * Returns true if and only if the server name is an IPv4 or IPv6
    * address.
    * @returns {boolean}
    */
    isIpLiteral() {
        const ret = wasm.servername_isIpLiteral(this.ptr);
        return ret !== 0;
    }
}
module.exports.ServerName = ServerName;
/**
* Data for a request to the `/keys/signatures/upload` API endpoint
* ([specification]).
*
* Publishes cross-signing signatures for the user.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#post_matrixclientv3keyssignaturesupload
*/
class SignatureUploadRequest {

    static __wrap(ptr) {
        const obj = Object.create(SignatureUploadRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signatureuploadrequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_signatureuploadrequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"signed_keys": …, "txn_id": …, "messages": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_signatureuploadrequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `SignatureUploadRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.signatureuploadrequest_new(addHeapObject(id), addHeapObject(body));
        return SignatureUploadRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.signatureuploadrequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.SignatureUploadRequest = SignatureUploadRequest;
/**
* Data for a request to the `/sendToDevice` API endpoint
* ([specification]).
*
* Send an event to a single device or to a group of devices.
*
* [specification]: https://spec.matrix.org/unstable/client-server-api/#put_matrixclientv3sendtodeviceeventtypetxnid
*/
class ToDeviceRequest {

    static __wrap(ptr) {
        const obj = Object.create(ToDeviceRequest.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_todevicerequest_free(ptr);
    }
    /**
    * The request ID.
    */
    get id() {
        const ret = wasm.__wbg_get_todevicerequest_id(this.ptr);
        return takeObject(ret);
    }
    /**
    * A JSON-encoded object of form:
    *
    * ```json
    * {"event_type": …, "txn_id": …, "messages": …}
    * ```
    */
    get body() {
        const ret = wasm.__wbg_get_todevicerequest_body(this.ptr);
        return takeObject(ret);
    }
    /**
    * Create a new `ToDeviceRequest`.
    * @param {string} id
    * @param {string} body
    */
    constructor(id, body) {
        const ret = wasm.todevicerequest_new(addHeapObject(id), addHeapObject(body));
        return ToDeviceRequest.__wrap(ret);
    }
    /**
    * Get its request type.
    * @returns {number}
    */
    get type() {
        const ret = wasm.todevicerequest_type(this.ptr);
        return ret >>> 0;
    }
}
module.exports.ToDeviceRequest = ToDeviceRequest;
/**
* A Matrix [user ID].
*
* [user ID]: https://spec.matrix.org/v1.2/appendices/#user-identifiers
*/
class UserId {

    static __wrap(ptr) {
        const obj = Object.create(UserId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_userid_free(ptr);
    }
    /**
    * Parse/validate and create a new `UserId`.
    * @param {string} id
    */
    constructor(id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.userid_new(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return UserId.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Returns the user's localpart.
    * @returns {string}
    */
    get localpart() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.userid_localpart(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Returns the server name of the user ID.
    * @returns {ServerName}
    */
    get serverName() {
        const ret = wasm.userid_serverName(this.ptr);
        return ServerName.__wrap(ret);
    }
    /**
    * Whether this user ID is a historical one.
    *
    * A historical user ID is one that doesn't conform to the latest
    * specification of the user ID grammar but is still accepted
    * because it was previously allowed.
    * @returns {boolean}
    */
    isHistorical() {
        const ret = wasm.userid_isHistorical(this.ptr);
        return ret !== 0;
    }
    /**
    * Return the user ID as a string.
    * @returns {string}
    */
    toString() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.userid_toString(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
module.exports.UserId = UserId;

module.exports.__wbindgen_object_drop_ref = function(arg0) {
    takeObject(arg0);
};

module.exports.__wbg_new_94fb1279cf6afea5 = function() {
    const ret = new Array();
    return addHeapObject(ret);
};

module.exports.__wbg_length_2cd798326f2cc4c1 = function(arg0) {
    const ret = getObject(arg0).length;
    return ret;
};

module.exports.__wbg_push_40c6a90f1805aa90 = function(arg0, arg1) {
    const ret = getObject(arg0).push(getObject(arg1));
    return ret;
};

module.exports.__wbg_olmmachine_new = function(arg0) {
    const ret = OlmMachine.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_decryptedroomevent_new = function(arg0) {
    const ret = DecryptedRoomEvent.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbindgen_object_clone_ref = function(arg0) {
    const ret = getObject(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_process_70251ed1291754d5 = function(arg0) {
    const ret = getObject(arg0).process;
    return addHeapObject(ret);
};

module.exports.__wbg_versions_b23f2588cdb2ddbb = function(arg0) {
    const ret = getObject(arg0).versions;
    return addHeapObject(ret);
};

module.exports.__wbg_node_61b8c9a82499895d = function(arg0) {
    const ret = getObject(arg0).node;
    return addHeapObject(ret);
};

module.exports.__wbindgen_is_string = function(arg0) {
    const ret = typeof(getObject(arg0)) === 'string';
    return ret;
};

module.exports.__wbg_require_2a93bc09fee45aca = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = getObject(arg0).require(getStringFromWasm0(arg1, arg2));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_crypto_2f56257a38275dbd = function(arg0) {
    const ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

module.exports.__wbg_msCrypto_d07655bf62361f21 = function(arg0) {
    const ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
};

module.exports.__wbindgen_is_object = function(arg0) {
    const val = getObject(arg0);
    const ret = typeof(val) === 'object' && val !== null;
    return ret;
};

module.exports.__wbg_static_accessor_NODE_MODULE_33b45247c55045b0 = function() {
    const ret = module;
    return addHeapObject(ret);
};

module.exports.__wbindgen_is_undefined = function(arg0) {
    const ret = getObject(arg0) === undefined;
    return ret;
};

module.exports.__wbg_static_accessor_MODULE_452b4680e8614c81 = function() {
    const ret = module;
    return addHeapObject(ret);
};

module.exports.__wbg_get_590a2cd912f2ae46 = function(arg0, arg1) {
    const ret = getObject(arg0)[arg1 >>> 0];
    return addHeapObject(ret);
};

module.exports.__wbg_next_bf3d83fc18df496e = function() { return handleError(function (arg0) {
    const ret = getObject(arg0).next();
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_done_040f966faa9a72b3 = function(arg0) {
    const ret = getObject(arg0).done;
    return ret;
};

module.exports.__wbg_value_419afbd9b9574c4c = function(arg0) {
    const ret = getObject(arg0).value;
    return addHeapObject(ret);
};

module.exports.__wbg_self_99737b4dcdf6f0d8 = function() { return handleError(function () {
    const ret = self.self;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_window_9b61fbbf3564c4fb = function() { return handleError(function () {
    const ret = window.window;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_globalThis_8e275ef40caea3a3 = function() { return handleError(function () {
    const ret = globalThis.globalThis;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_global_5de1e0f82bddcd27 = function() { return handleError(function () {
    const ret = global.global;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_newnoargs_e23b458e372830de = function(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

module.exports.__wbg_call_ae78342adc33730a = function() { return handleError(function (arg0, arg1) {
    const ret = getObject(arg0).call(getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_call_3ed288a247f13ea5 = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_new_37705eed627d5ed9 = function(arg0, arg1) {
    try {
        var state0 = {a: arg0, b: arg1};
        var cb0 = (arg0, arg1) => {
            const a = state0.a;
            state0.a = 0;
            try {
                return __wbg_adapter_105(a, state0.b, arg0, arg1);
            } finally {
                state0.a = a;
            }
        };
        const ret = new Promise(cb0);
        return addHeapObject(ret);
    } finally {
        state0.a = state0.b = 0;
    }
};

module.exports.__wbg_length_0acb1cf9bbaf8519 = function(arg0) {
    const ret = getObject(arg0).length;
    return ret;
};

module.exports.__wbindgen_memory = function() {
    const ret = wasm.memory;
    return addHeapObject(ret);
};

module.exports.__wbg_buffer_7af23f65f6c64548 = function(arg0) {
    const ret = getObject(arg0).buffer;
    return addHeapObject(ret);
};

module.exports.__wbg_new_cc9018bd6f283b6f = function(arg0) {
    const ret = new Uint8Array(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_set_f25e869e4565d2a2 = function(arg0, arg1, arg2) {
    getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

module.exports.__wbg_newwithlength_8f0657faca9f1422 = function(arg0) {
    const ret = new Uint8Array(arg0 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbg_subarray_da527dbd24eafb6b = function(arg0, arg1, arg2) {
    const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbindgen_string_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'string' ? obj : undefined;
    var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbg_now_04bcd3bf9fb6165e = function() {
    const ret = Date.now();
    return ret;
};

module.exports.__wbg_new_8b59f35c3b358b73 = function(arg0) {
    const ret = new Set(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_add_8852099ac18dc907 = function(arg0, arg1) {
    const ret = getObject(arg0).add(getObject(arg1));
    return addHeapObject(ret);
};

module.exports.__wbg_entries_b76c49f92ac283c4 = function(arg0) {
    const ret = getObject(arg0).entries();
    return addHeapObject(ret);
};

module.exports.__wbg_values_fe290b3bc9de1ceb = function(arg0) {
    const ret = getObject(arg0).values();
    return addHeapObject(ret);
};

module.exports.__wbg_keysuploadrequest_new = function(arg0) {
    const ret = KeysUploadRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_keysbackuprequest_new = function(arg0) {
    const ret = KeysBackupRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_roommessagerequest_new = function(arg0) {
    const ret = RoomMessageRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_signatureuploadrequest_new = function(arg0) {
    const ret = SignatureUploadRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_todevicerequest_new = function(arg0) {
    const ret = ToDeviceRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_keysqueryrequest_new = function(arg0) {
    const ret = KeysQueryRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_keysclaimrequest_new = function(arg0) {
    const ret = KeysClaimRequest.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbg_userid_new = function(arg0) {
    const ret = UserId.__wrap(arg0);
    return addHeapObject(ret);
};

module.exports.__wbindgen_error_new = function(arg0, arg1) {
    const ret = new Error(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

module.exports.__wbindgen_string_new = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

module.exports.__wbg_from_7b9a99a7cd3ef15f = function(arg0) {
    const ret = Array.from(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_at_eb83680223f3b691 = function(arg0, arg1) {
    const ret = getObject(arg0).at(arg1);
    return addHeapObject(ret);
};

module.exports.__wbindgen_number_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'number' ? obj : undefined;
    getFloat64Memory0()[arg0 / 8 + 1] = isLikeNone(ret) ? 0 : ret;
    getInt32Memory0()[arg0 / 4 + 0] = !isLikeNone(ret);
};

module.exports.__wbg_getPrototypeOf_34c9223646177256 = function(arg0) {
    const ret = Object.getPrototypeOf(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_constructor_5abd6dfea8e0d4ee = function(arg0) {
    const ret = getObject(arg0).constructor;
    return addHeapObject(ret);
};

module.exports.__wbg_name_ca974f6ed2be667c = function(arg0) {
    const ret = getObject(arg0).name;
    return addHeapObject(ret);
};

module.exports.__wbg_get_a9cab131e3152c49 = function() { return handleError(function (arg0, arg1) {
    const ret = Reflect.get(getObject(arg0), getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_self_86b4b13392c7af56 = function() { return handleError(function () {
    const ret = self.self;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_crypto_b8c92eaac23d0d80 = function(arg0) {
    const ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

module.exports.__wbg_msCrypto_9ad6677321a08dd8 = function(arg0) {
    const ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
};

module.exports.__wbg_require_f5521a5b85ad2542 = function(arg0, arg1, arg2) {
    const ret = getObject(arg0).require(getStringFromWasm0(arg1, arg2));
    return addHeapObject(ret);
};

module.exports.__wbg_getRandomValues_dd27e6b0652b3236 = function(arg0) {
    const ret = getObject(arg0).getRandomValues;
    return addHeapObject(ret);
};

module.exports.__wbg_randomFillSync_d2ba53160aec6aba = function(arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
};

module.exports.__wbg_getRandomValues_e57c9b75ddead065 = function(arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
};

module.exports.__wbg_randomFillSync_654a7797990fb8db = function() { return handleError(function (arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
}, arguments) };

module.exports.__wbg_getRandomValues_fb6b088efb6bead2 = function() { return handleError(function (arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
}, arguments) };

module.exports.__wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

module.exports.__wbg_resolve_a9a87bdd64e9e62c = function(arg0) {
    const ret = Promise.resolve(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbindgen_cb_drop = function(arg0) {
    const obj = takeObject(arg0).original;
    if (obj.cnt-- == 1) {
        obj.a = 0;
        return true;
    }
    const ret = false;
    return ret;
};

module.exports.__wbg_then_ce526c837d07b68f = function(arg0, arg1) {
    const ret = getObject(arg0).then(getObject(arg1));
    return addHeapObject(ret);
};

module.exports.__wbindgen_closure_wrapper8963 = function(arg0, arg1, arg2) {
    const ret = makeMutClosure(arg0, arg1, 101, __wbg_adapter_26);
    return addHeapObject(ret);
};

const path = require('path').join(__dirname, 'matrix_sdk_crypto_bg.wasm');
const bytes = require('fs').readFileSync(path);

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
wasm = wasmInstance.exports;
module.exports.__wasm = wasm;

