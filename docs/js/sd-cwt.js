var SDCWT = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __typeError = (msg) => {
    throw TypeError(msg);
  };
  var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
  var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
  var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
  var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
  var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
  var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
  var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
  var __privateWrapper = (obj, member, setter, getter) => ({
    set _(value) {
      __privateSet(obj, member, value, setter);
    },
    get _() {
      return __privateGet(obj, member, getter);
    }
  });

  // src/browser.js
  var browser_exports = {};
  __export(browser_exports, {
    Algorithm: () => Algorithm,
    ClaimKey: () => ClaimKey,
    CoseCurve: () => CoseCurve,
    CoseKeyParam: () => CoseKeyParam,
    CoseKeyType: () => CoseKeyType,
    EDN: () => EDN,
    HeaderParam: () => HeaderParam2,
    Hex: () => Hex,
    Holder: () => Holder,
    Issuer: () => Issuer,
    MAX_DEPTH: () => MAX_DEPTH,
    MediaType: () => MediaType,
    Utils: () => Utils,
    Verifier: () => Verifier,
    assertClaimsClean: () => assertClaimsClean,
    cbor: () => lib_exports,
    coseKeyFromHex: () => coseKeyFromHex,
    coseKeyToHex: () => coseKeyToHex,
    coseKeyToInternal: () => coseKeyToInternal,
    coseSign1: () => cose_sign1_exports,
    deserializeCoseKey: () => deserializeCoseKey,
    ednCbor: () => lib_exports,
    formatClaims: () => formatClaims,
    generateKeyPair: () => generateKeyPair2,
    getAlgorithmFromCoseKey: () => getAlgorithmFromCoseKey,
    internalToCoseKey: () => internalToCoseKey,
    isCoseKey: () => isCoseKey,
    sdCwt: () => sd_cwt_exports,
    serializeCoseKey: () => serializeCoseKey,
    toBeDecoy: () => toBeDecoy,
    toBeRedacted: () => toBeRedacted,
    validateClaimsClean: () => validateClaimsClean
  });

  // src/buffer-shim.js
  var BufferShim = class _BufferShim extends Uint8Array {
    constructor(input, byteOffsetOrEncoding, byteLength) {
      if (input instanceof ArrayBuffer && typeof byteOffsetOrEncoding === "number") {
        super(input, byteOffsetOrEncoding, byteLength);
      } else if (typeof input === "number") {
        super(input);
      } else if (typeof input === "string") {
        const bytes = _BufferShim._fromString(input, byteOffsetOrEncoding);
        super(bytes);
      } else if (input instanceof ArrayBuffer) {
        super(input);
      } else if (ArrayBuffer.isView(input)) {
        super([...new Uint8Array(input.buffer, input.byteOffset, input.byteLength)]);
      } else if (Array.isArray(input)) {
        super(input);
      } else if (input && typeof input === "object" && "type" in input && input.type === "Buffer") {
        super(input.data);
      } else {
        super(input || 0);
      }
    }
    static _fromString(str, encoding = "utf8") {
      if (encoding === "hex") {
        const hex = str.replace(/\s/g, "");
        const bytes = new Uint8Array(hex.length / 2);
        for (let i3 = 0; i3 < bytes.length; i3++) {
          bytes[i3] = parseInt(hex.substr(i3 * 2, 2), 16);
        }
        return bytes;
      } else if (encoding === "base64" || encoding === "base64url") {
        let base64 = str;
        if (encoding === "base64url") {
          base64 = base64.replace(/-/g, "+").replace(/_/g, "/");
          const pad = base64.length % 4;
          if (pad) {
            base64 += "=".repeat(4 - pad);
          }
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i3 = 0; i3 < binary.length; i3++) {
          bytes[i3] = binary.charCodeAt(i3);
        }
        return bytes;
      } else {
        return new TextEncoder().encode(str);
      }
    }
    static from(input, encoding) {
      if (typeof input === "string") {
        return new _BufferShim(_BufferShim._fromString(input, encoding));
      }
      if (input instanceof ArrayBuffer) {
        return new _BufferShim(input);
      }
      if (ArrayBuffer.isView(input)) {
        return new _BufferShim(input);
      }
      if (Array.isArray(input)) {
        return new _BufferShim(input);
      }
      if (input && typeof input === "object" && "type" in input && input.type === "Buffer") {
        return new _BufferShim(input.data);
      }
      return new _BufferShim(input);
    }
    static isBuffer(obj) {
      return obj instanceof _BufferShim || obj instanceof Uint8Array && obj.constructor.name === "Buffer";
    }
    static alloc(size, fill = 0) {
      const buf = new _BufferShim(size);
      if (fill !== 0) {
        buf.fill(fill);
      }
      return buf;
    }
    static allocUnsafe(size) {
      return new _BufferShim(size);
    }
    static concat(list, totalLength) {
      if (totalLength === void 0) {
        totalLength = list.reduce((acc, buf) => acc + buf.length, 0);
      }
      const result = new _BufferShim(totalLength);
      let offset = 0;
      for (const buf of list) {
        result.set(buf, offset);
        offset += buf.length;
      }
      return result;
    }
    toString(encoding = "utf8") {
      if (encoding === "hex") {
        return Array.from(this).map((b4) => b4.toString(16).padStart(2, "0")).join("");
      } else if (encoding === "base64") {
        let binary = "";
        for (let i3 = 0; i3 < this.length; i3++) {
          binary += String.fromCharCode(this[i3]);
        }
        return btoa(binary);
      } else if (encoding === "base64url") {
        let binary = "";
        for (let i3 = 0; i3 < this.length; i3++) {
          binary += String.fromCharCode(this[i3]);
        }
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      } else {
        return new TextDecoder().decode(this);
      }
    }
    toJSON() {
      return {
        type: "Buffer",
        data: Array.from(this)
      };
    }
    slice(start, end) {
      return new _BufferShim(this.subarray(start, end));
    }
    copy(target, targetStart = 0, sourceStart = 0, sourceEnd = this.length) {
      const source = this.subarray(sourceStart, sourceEnd);
      target.set(source, targetStart);
      return source.length;
    }
    equals(other) {
      if (this.length !== other.length) return false;
      for (let i3 = 0; i3 < this.length; i3++) {
        if (this[i3] !== other[i3]) return false;
      }
      return true;
    }
    compare(other) {
      const len = Math.min(this.length, other.length);
      for (let i3 = 0; i3 < len; i3++) {
        if (this[i3] < other[i3]) return -1;
        if (this[i3] > other[i3]) return 1;
      }
      if (this.length < other.length) return -1;
      if (this.length > other.length) return 1;
      return 0;
    }
    readUInt32BE(offset = 0) {
      return (this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]) >>> 0;
    }
    writeUInt32BE(value, offset = 0) {
      this[offset] = value >>> 24 & 255;
      this[offset + 1] = value >>> 16 & 255;
      this[offset + 2] = value >>> 8 & 255;
      this[offset + 3] = value & 255;
      return offset + 4;
    }
  };
  Object.getOwnPropertyNames(Uint8Array).forEach((prop) => {
    if (!(prop in BufferShim) && typeof Uint8Array[prop] === "function") {
      BufferShim[prop] = Uint8Array[prop];
    }
  });
  var Buffer2 = BufferShim;

  // node_modules/cbor2/lib/index.js
  var lib_exports = {};
  __export(lib_exports, {
    DiagnosticSizes: () => o3,
    SequenceEvents: () => O4,
    Simple: () => t2,
    Tag: () => i,
    TypeEncoderMap: () => s2,
    Writer: () => e,
    cdeDecodeOptions: () => r,
    cdeEncodeOptions: () => F,
    comment: () => L,
    dcborDecodeOptions: () => n,
    dcborEncodeOptions: () => H,
    decode: () => l5,
    decodeSequence: () => b3,
    defaultDecodeOptions: () => d4,
    defaultEncodeOptions: () => k,
    diagnose: () => M,
    encode: () => Q,
    encodedNumber: () => de,
    getEncoded: () => f2,
    saveEncoded: () => u,
    saveEncodedLength: () => l,
    unbox: () => t,
    version: () => o4
  });

  // node_modules/cbor2/lib/constants.js
  var f = { POS_INT: 0, NEG_INT: 1, BYTE_STRING: 2, UTF8_STRING: 3, ARRAY: 4, MAP: 5, TAG: 6, SIMPLE_FLOAT: 7 };
  var I = { DATE_STRING: 0, DATE_EPOCH: 1, POS_BIGINT: 2, NEG_BIGINT: 3, DECIMAL_FRAC: 4, BIGFLOAT: 5, BASE64URL_EXPECTED: 21, BASE64_EXPECTED: 22, BASE16_EXPECTED: 23, CBOR: 24, URI: 32, BASE64URL: 33, BASE64: 34, MIME: 36, SET: 258, JSON: 262, WTF8: 273, REGEXP: 21066, SELF_DESCRIBED: 55799, INVALID_16: 65535, INVALID_32: 4294967295, INVALID_64: 0xffffffffffffffffn };
  var o = { ZERO: 0, ONE: 24, TWO: 25, FOUR: 26, EIGHT: 27, INDEFINITE: 31 };
  var T = { FALSE: 20, TRUE: 21, NULL: 22, UNDEFINED: 23 };
  var N = class {
  };
  __publicField(N, "BREAK", Symbol.for("github.com/hildjj/cbor2/break"));
  __publicField(N, "ENCODED", Symbol.for("github.com/hildjj/cbor2/cbor-encoded"));
  __publicField(N, "LENGTH", Symbol.for("github.com/hildjj/cbor2/length"));
  var S = { MIN: -(2n ** 63n), MAX: 2n ** 64n - 1n };

  // node_modules/cbor2/lib/tag.js
  var _e;
  var _i = class _i {
    constructor(e2, t3 = void 0) {
      __publicField(this, "tag");
      __publicField(this, "contents");
      this.tag = e2, this.contents = t3;
    }
    get noChildren() {
      return !!__privateGet(_i, _e).get(this.tag)?.noChildren;
    }
    static registerDecoder(e2, t3, n2) {
      const o5 = __privateGet(this, _e).get(e2);
      return __privateGet(this, _e).set(e2, t3), o5 && ("comment" in t3 || (t3.comment = o5.comment), "noChildren" in t3 || (t3.noChildren = o5.noChildren)), n2 && !t3.comment && (t3.comment = () => `(${n2})`), o5;
    }
    static clearDecoder(e2) {
      const t3 = __privateGet(this, _e).get(e2);
      return __privateGet(this, _e).delete(e2), t3;
    }
    static getDecoder(e2) {
      return __privateGet(this, _e).get(e2);
    }
    static getAllDecoders() {
      return new Map(__privateGet(this, _e));
    }
    *[Symbol.iterator]() {
      yield this.contents;
    }
    push(e2) {
      return this.contents = e2, 1;
    }
    decode(e2) {
      const t3 = e2?.tags?.get(this.tag) ?? __privateGet(_i, _e).get(this.tag);
      return t3 ? t3(this, e2) : this;
    }
    comment(e2, t3) {
      const n2 = e2?.tags?.get(this.tag) ?? __privateGet(_i, _e).get(this.tag);
      if (n2?.comment) return n2.comment(this, e2, t3);
    }
    toCBOR() {
      return [this.tag, this.contents];
    }
    [Symbol.for("nodejs.util.inspect.custom")](e2, t3, n2) {
      return `${this.tag}(${n2(this.contents, t3)})`;
    }
  };
  _e = new WeakMap();
  __privateAdd(_i, _e, /* @__PURE__ */ new Map());
  var i = _i;

  // node_modules/cbor2/lib/box.js
  function f2(n2) {
    if (n2 != null && typeof n2 == "object") return n2[N.ENCODED];
  }
  function s(n2) {
    if (n2 != null && typeof n2 == "object") return n2[N.LENGTH];
  }
  function u(n2, e2) {
    Object.defineProperty(n2, N.ENCODED, { configurable: true, enumerable: false, value: e2 });
  }
  function l(n2, e2) {
    Object.defineProperty(n2, N.LENGTH, { configurable: true, enumerable: false, value: e2 });
  }
  function d(n2, e2) {
    const r2 = Object(n2);
    return u(r2, e2), r2;
  }
  function t(n2) {
    if (!n2 || typeof n2 != "object") return n2;
    switch (n2.constructor) {
      case BigInt:
      case Boolean:
      case Number:
      case String:
      case Symbol:
        return n2.valueOf();
      case Array:
        return n2.map((e2) => t(e2));
      case Map: {
        const e2 = t([...n2.entries()]);
        return e2.every(([r2]) => typeof r2 == "string") ? Object.fromEntries(e2) : new Map(e2);
      }
      case i:
        return new i(t(n2.tag), t(n2.contents));
      case Object: {
        const e2 = {};
        for (const [r2, a3] of Object.entries(n2)) e2[r2] = t(a3);
        return e2;
      }
    }
    return n2;
  }

  // node_modules/cbor2/lib/utils.js
  var g = Symbol("CBOR_RANGES");
  function c(r2, n2) {
    Object.defineProperty(r2, g, { configurable: false, enumerable: false, writable: false, value: n2 });
  }
  function f3(r2) {
    return r2[g];
  }
  function l2(r2) {
    return f3(r2) !== void 0;
  }
  function R(r2, n2 = 0, t3 = r2.length - 1) {
    const o5 = r2.subarray(n2, t3), a3 = f3(r2);
    if (a3) {
      const s4 = [];
      for (const e2 of a3) if (e2[0] >= n2 && e2[0] + e2[1] <= t3) {
        const i3 = [...e2];
        i3[0] -= n2, s4.push(i3);
      }
      s4.length && c(o5, s4);
    }
    return o5;
  }
  function b(r2) {
    let n2 = Math.ceil(r2.length / 2);
    const t3 = new Uint8Array(n2);
    n2--;
    for (let o5 = r2.length, a3 = o5 - 2; o5 >= 0; o5 = a3, a3 -= 2, n2--) t3[n2] = parseInt(r2.substring(a3, o5), 16);
    return t3;
  }
  function A(r2) {
    return r2.reduce((n2, t3) => n2 + t3.toString(16).padStart(2, "0"), "");
  }
  function d2(r2) {
    const n2 = r2.reduce((e2, i3) => e2 + i3.length, 0), t3 = r2.some((e2) => l2(e2)), o5 = [], a3 = new Uint8Array(n2);
    let s4 = 0;
    for (const e2 of r2) {
      if (!(e2 instanceof Uint8Array)) throw new TypeError(`Invalid array: ${e2}`);
      if (a3.set(e2, s4), t3) {
        const i3 = e2[g] ?? [[0, e2.length]];
        for (const u2 of i3) u2[0] += s4;
        o5.push(...i3);
      }
      s4 += e2.length;
    }
    return t3 && c(a3, o5), a3;
  }
  function y(r2) {
    const n2 = atob(r2);
    return Uint8Array.from(n2, (t3) => t3.codePointAt(0));
  }
  var p = { "-": "+", _: "/" };
  function x(r2) {
    const n2 = r2.replace(/[_-]/g, (t3) => p[t3]);
    return y(n2.padEnd(Math.ceil(n2.length / 4) * 4, "="));
  }
  function h() {
    const r2 = new Uint8Array(4), n2 = new Uint32Array(r2.buffer);
    return !((n2[0] = 1) & r2[0]);
  }
  function U(r2) {
    let n2 = "";
    for (const t3 of r2) {
      const o5 = t3.codePointAt(0)?.toString(16).padStart(4, "0");
      n2 && (n2 += ", "), n2 += `U+${o5}`;
    }
    return n2;
  }

  // node_modules/cbor2/lib/typeEncoderMap.js
  var _e2;
  var s2 = class {
    constructor() {
      __privateAdd(this, _e2, /* @__PURE__ */ new Map());
    }
    registerEncoder(e2, t3) {
      const n2 = __privateGet(this, _e2).get(e2);
      return __privateGet(this, _e2).set(e2, t3), n2;
    }
    get(e2) {
      return __privateGet(this, _e2).get(e2);
    }
    delete(e2) {
      return __privateGet(this, _e2).delete(e2);
    }
    clear() {
      __privateGet(this, _e2).clear();
    }
  };
  _e2 = new WeakMap();

  // node_modules/cbor2/lib/sorts.js
  function f4(c4, d5) {
    const [u2, a3, n2] = c4, [l6, s4, t3] = d5, r2 = Math.min(n2.length, t3.length);
    for (let o5 = 0; o5 < r2; o5++) {
      const e2 = n2[o5] - t3[o5];
      if (e2 !== 0) return e2;
    }
    return 0;
  }

  // node_modules/cbor2/lib/writer.js
  var _r, _i2, _s, _t, _a, _e_instances, n_fn, o_fn, l_fn, e_fn, h_fn;
  var _e3 = class _e3 {
    constructor(t3 = {}) {
      __privateAdd(this, _e_instances);
      __privateAdd(this, _r);
      __privateAdd(this, _i2, []);
      __privateAdd(this, _s, null);
      __privateAdd(this, _t, 0);
      __privateAdd(this, _a, 0);
      if (__privateSet(this, _r, { ..._e3.defaultOptions, ...t3 }), __privateGet(this, _r).chunkSize < 8) throw new RangeError(`Expected size >= 8, got ${__privateGet(this, _r).chunkSize}`);
      __privateMethod(this, _e_instances, n_fn).call(this);
    }
    get length() {
      return __privateGet(this, _a);
    }
    read() {
      __privateMethod(this, _e_instances, o_fn).call(this);
      const t3 = new Uint8Array(__privateGet(this, _a));
      let i3 = 0;
      for (const s4 of __privateGet(this, _i2)) t3.set(s4, i3), i3 += s4.length;
      return __privateMethod(this, _e_instances, n_fn).call(this), t3;
    }
    write(t3) {
      const i3 = t3.length;
      i3 > __privateMethod(this, _e_instances, l_fn).call(this) ? (__privateMethod(this, _e_instances, o_fn).call(this), i3 > __privateGet(this, _r).chunkSize ? (__privateGet(this, _i2).push(t3), __privateMethod(this, _e_instances, n_fn).call(this)) : (__privateMethod(this, _e_instances, n_fn).call(this), __privateGet(this, _i2)[__privateGet(this, _i2).length - 1].set(t3), __privateSet(this, _t, i3))) : (__privateGet(this, _i2)[__privateGet(this, _i2).length - 1].set(t3, __privateGet(this, _t)), __privateSet(this, _t, __privateGet(this, _t) + i3)), __privateSet(this, _a, __privateGet(this, _a) + i3);
    }
    writeUint8(t3) {
      __privateMethod(this, _e_instances, e_fn).call(this, 1), __privateGet(this, _s).setUint8(__privateGet(this, _t), t3), __privateMethod(this, _e_instances, h_fn).call(this, 1);
    }
    writeUint16(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 2), __privateGet(this, _s).setUint16(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 2);
    }
    writeUint32(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 4), __privateGet(this, _s).setUint32(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 4);
    }
    writeBigUint64(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 8), __privateGet(this, _s).setBigUint64(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 8);
    }
    writeInt16(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 2), __privateGet(this, _s).setInt16(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 2);
    }
    writeInt32(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 4), __privateGet(this, _s).setInt32(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 4);
    }
    writeBigInt64(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 8), __privateGet(this, _s).setBigInt64(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 8);
    }
    writeFloat32(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 4), __privateGet(this, _s).setFloat32(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 4);
    }
    writeFloat64(t3, i3 = false) {
      __privateMethod(this, _e_instances, e_fn).call(this, 8), __privateGet(this, _s).setFloat64(__privateGet(this, _t), t3, i3), __privateMethod(this, _e_instances, h_fn).call(this, 8);
    }
    clear() {
      __privateSet(this, _a, 0), __privateSet(this, _i2, []), __privateMethod(this, _e_instances, n_fn).call(this);
    }
  };
  _r = new WeakMap();
  _i2 = new WeakMap();
  _s = new WeakMap();
  _t = new WeakMap();
  _a = new WeakMap();
  _e_instances = new WeakSet();
  n_fn = function() {
    const t3 = new Uint8Array(__privateGet(this, _r).chunkSize);
    __privateGet(this, _i2).push(t3), __privateSet(this, _t, 0), __privateSet(this, _s, new DataView(t3.buffer, t3.byteOffset, t3.byteLength));
  };
  o_fn = function() {
    if (__privateGet(this, _t) === 0) {
      __privateGet(this, _i2).pop();
      return;
    }
    const t3 = __privateGet(this, _i2).length - 1;
    __privateGet(this, _i2)[t3] = __privateGet(this, _i2)[t3].subarray(0, __privateGet(this, _t)), __privateSet(this, _t, 0), __privateSet(this, _s, null);
  };
  l_fn = function() {
    const t3 = __privateGet(this, _i2).length - 1;
    return __privateGet(this, _i2)[t3].length - __privateGet(this, _t);
  };
  e_fn = function(t3) {
    __privateMethod(this, _e_instances, l_fn).call(this) < t3 && (__privateMethod(this, _e_instances, o_fn).call(this), __privateMethod(this, _e_instances, n_fn).call(this));
  };
  h_fn = function(t3) {
    __privateSet(this, _t, __privateGet(this, _t) + t3), __privateSet(this, _a, __privateGet(this, _a) + t3);
  };
  __publicField(_e3, "defaultOptions", { chunkSize: 4096 });
  var e = _e3;

  // node_modules/cbor2/lib/float.js
  function o2(e2, n2 = 0, t3 = false) {
    const r2 = e2[n2] & 128 ? -1 : 1, f6 = (e2[n2] & 124) >> 2, a3 = (e2[n2] & 3) << 8 | e2[n2 + 1];
    if (f6 === 0) {
      if (t3 && a3 !== 0) throw new Error(`Unwanted subnormal: ${r2 * 5960464477539063e-23 * a3}`);
      return r2 * 5960464477539063e-23 * a3;
    } else if (f6 === 31) return a3 ? NaN : r2 * (1 / 0);
    return r2 * 2 ** (f6 - 25) * (1024 + a3);
  }
  function s3(e2) {
    const n2 = new DataView(new ArrayBuffer(4));
    n2.setFloat32(0, e2, false);
    const t3 = n2.getUint32(0, false);
    if ((t3 & 8191) !== 0) return null;
    let r2 = t3 >> 16 & 32768;
    const f6 = t3 >> 23 & 255, a3 = t3 & 8388607;
    if (!(f6 === 0 && a3 === 0)) if (f6 >= 113 && f6 <= 142) r2 += (f6 - 112 << 10) + (a3 >> 13);
    else if (f6 >= 103 && f6 < 113) {
      if (a3 & (1 << 126 - f6) - 1) return null;
      r2 += a3 + 8388608 >> 126 - f6;
    } else if (f6 === 255) r2 |= 31744, r2 |= a3 >> 13;
    else return null;
    return r2;
  }
  function i2(e2) {
    if (e2 !== 0) {
      const n2 = new ArrayBuffer(8), t3 = new DataView(n2);
      t3.setFloat64(0, e2, false);
      const r2 = t3.getBigUint64(0, false);
      if ((r2 & 0x7ff0000000000000n) === 0n) return r2 & 0x8000000000000000n ? -0 : 0;
    }
    return e2;
  }
  function l3(e2) {
    switch (e2.length) {
      case 2:
        o2(e2, 0, true);
        break;
      case 4: {
        const n2 = new DataView(e2.buffer, e2.byteOffset, e2.byteLength), t3 = n2.getUint32(0, false);
        if ((t3 & 2139095040) === 0 && t3 & 8388607) throw new Error(`Unwanted subnormal: ${n2.getFloat32(0, false)}`);
        break;
      }
      case 8: {
        const n2 = new DataView(e2.buffer, e2.byteOffset, e2.byteLength), t3 = n2.getBigUint64(0, false);
        if ((t3 & 0x7ff0000000000000n) === 0n && t3 & 0x000fffffffffffn) throw new Error(`Unwanted subnormal: ${n2.getFloat64(0, false)}`);
        break;
      }
      default:
        throw new TypeError(`Bad input to isSubnormal: ${e2}`);
    }
  }

  // node_modules/@cto.af/wtf8/lib/errors.js
  var DecodeError = class extends TypeError {
    constructor() {
      super("The encoded data was not valid for encoding wtf-8");
      __publicField(this, "code", "ERR_ENCODING_INVALID_ENCODED_DATA");
    }
  };
  var InvalidEncodingError = class extends RangeError {
    constructor(label) {
      super(`Invalid encoding: "${label}"`);
      __publicField(this, "code", "ERR_ENCODING_NOT_SUPPORTED");
    }
  };

  // node_modules/@cto.af/wtf8/lib/const.js
  var BOM = 65279;
  var EMPTY = new Uint8Array(0);
  var MIN_HIGH_SURROGATE = 55296;
  var MIN_LOW_SURROGATE = 56320;
  var REPLACEMENT = 65533;
  var WTF8 = "wtf-8";

  // node_modules/@cto.af/wtf8/lib/decode.js
  function isArrayBufferView(input) {
    return input && !(input instanceof ArrayBuffer) && input.buffer instanceof ArrayBuffer;
  }
  function getUint8(input) {
    if (!input) {
      return EMPTY;
    }
    if (input instanceof Uint8Array) {
      return input;
    }
    if (isArrayBufferView(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    return new Uint8Array(input);
  }
  var REMAINDER = [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    -1,
    -1,
    -1,
    -1,
    1,
    1,
    2,
    3
  ];
  var _left, _cur, _pending, _first, _buf;
  var _Wtf8Decoder = class _Wtf8Decoder {
    constructor(label = "wtf8", options = void 0) {
      __publicField(this, "encoding", WTF8);
      __publicField(this, "fatal");
      __publicField(this, "ignoreBOM");
      __publicField(this, "bufferSize");
      __privateAdd(this, _left, 0);
      __privateAdd(this, _cur, 0);
      __privateAdd(this, _pending, 0);
      __privateAdd(this, _first, true);
      __privateAdd(this, _buf);
      if (label.toLowerCase().replace("-", "") !== "wtf8") {
        throw new InvalidEncodingError(label);
      }
      this.fatal = Boolean(options?.fatal);
      this.ignoreBOM = Boolean(options?.ignoreBOM);
      this.bufferSize = Math.floor(options?.bufferSize ?? _Wtf8Decoder.DEFAULT_BUFFERSIZE);
      if (isNaN(this.bufferSize) || this.bufferSize < 1) {
        throw new RangeError(`Invalid buffer size: ${options?.bufferSize}`);
      }
      __privateSet(this, _buf, new Uint16Array(this.bufferSize));
    }
    decode(input, options) {
      const streaming = Boolean(options?.stream);
      const bytes = getUint8(input);
      const res = [];
      const out = __privateGet(this, _buf);
      const maxSize = this.bufferSize - 3;
      let pos = 0;
      const fatal = () => {
        __privateSet(this, _cur, 0);
        __privateSet(this, _left, 0);
        __privateSet(this, _pending, 0);
        if (this.fatal) {
          throw new DecodeError();
        }
        out[pos++] = REPLACEMENT;
      };
      const fatals = () => {
        const p4 = __privateGet(this, _pending);
        for (let i3 = 0; i3 < p4; i3++) {
          fatal();
        }
      };
      const oneByte = (b4) => {
        if (__privateGet(this, _left) === 0) {
          const n2 = REMAINDER[b4 >> 4];
          switch (n2) {
            case -1:
              fatal();
              break;
            case 0:
              out[pos++] = b4;
              break;
            case 1:
              __privateSet(this, _cur, b4 & 31);
              if ((__privateGet(this, _cur) & 30) === 0) {
                fatal();
              } else {
                __privateSet(this, _left, 1);
                __privateSet(this, _pending, 1);
              }
              break;
            case 2:
              __privateSet(this, _cur, b4 & 15);
              __privateSet(this, _left, 2);
              __privateSet(this, _pending, 1);
              break;
            case 3:
              if (b4 & 8) {
                fatal();
              } else {
                __privateSet(this, _cur, b4 & 7);
                __privateSet(this, _left, 3);
                __privateSet(this, _pending, 1);
              }
              break;
          }
        } else {
          if ((b4 & 192) !== 128) {
            fatals();
            return oneByte(b4);
          }
          if (__privateGet(this, _pending) === 1 && __privateGet(this, _left) === 2 && __privateGet(this, _cur) === 0 && (b4 & 32) === 0) {
            fatals();
            return oneByte(b4);
          }
          if (__privateGet(this, _left) === 3 && __privateGet(this, _cur) === 0 && (b4 & 48) === 0) {
            fatals();
            return oneByte(b4);
          }
          __privateSet(this, _cur, __privateGet(this, _cur) << 6 | b4 & 63);
          __privateWrapper(this, _pending)._++;
          if (--__privateWrapper(this, _left)._ === 0) {
            if (this.ignoreBOM || !__privateGet(this, _first) || __privateGet(this, _cur) !== BOM) {
              if (__privateGet(this, _cur) < 65536) {
                out[pos++] = __privateGet(this, _cur);
              } else {
                const cp = __privateGet(this, _cur) - 65536;
                out[pos++] = cp >>> 10 & 1023 | MIN_HIGH_SURROGATE;
                out[pos++] = cp & 1023 | MIN_LOW_SURROGATE;
              }
            }
            __privateSet(this, _cur, 0);
            __privateSet(this, _pending, 0);
            __privateSet(this, _first, false);
          }
        }
      };
      for (const b4 of bytes) {
        if (pos >= maxSize) {
          res.push(String.fromCharCode.apply(null, out.subarray(0, pos)));
          pos = 0;
        }
        oneByte(b4);
      }
      if (!streaming) {
        __privateSet(this, _first, true);
        if (__privateGet(this, _cur) || __privateGet(this, _left)) {
          fatals();
        }
      }
      if (pos > 0) {
        res.push(String.fromCharCode.apply(null, out.subarray(0, pos)));
      }
      return res.join("");
    }
  };
  _left = new WeakMap();
  _cur = new WeakMap();
  _pending = new WeakMap();
  _first = new WeakMap();
  _buf = new WeakMap();
  __publicField(_Wtf8Decoder, "DEFAULT_BUFFERSIZE", 4096);
  var Wtf8Decoder = _Wtf8Decoder;

  // node_modules/@cto.af/wtf8/lib/encode.js
  function utf8length(str) {
    let len = 0;
    for (const s4 of str) {
      const cp = s4.codePointAt(0);
      if (cp < 128) {
        len++;
      } else if (cp < 2048) {
        len += 2;
      } else if (cp < 65536) {
        len += 3;
      } else {
        len += 4;
      }
    }
    return len;
  }
  var Wtf8Encoder = class {
    constructor() {
      __publicField(this, "encoding", WTF8);
    }
    encode(input) {
      if (!input) {
        return EMPTY;
      }
      const buf = new Uint8Array(utf8length(String(input)));
      this.encodeInto(input, buf);
      return buf;
    }
    encodeInto(source, destination) {
      const str = String(source);
      const len = str.length;
      const outLen = destination.length;
      let written = 0;
      let read = 0;
      for (read = 0; read < len; read++) {
        const c4 = str.codePointAt(read);
        if (c4 < 128) {
          if (written >= outLen) {
            break;
          }
          destination[written++] = c4;
        } else if (c4 < 2048) {
          if (written >= outLen - 1) {
            break;
          }
          destination[written++] = 192 | c4 >> 6;
          destination[written++] = 128 | c4 & 63;
        } else if (c4 < 65536) {
          if (written >= outLen - 2) {
            break;
          }
          destination[written++] = 224 | c4 >> 12;
          destination[written++] = 128 | c4 >> 6 & 63;
          destination[written++] = 128 | c4 & 63;
        } else {
          if (written >= outLen - 3) {
            break;
          }
          destination[written++] = 240 | c4 >> 18;
          destination[written++] = 128 | c4 >> 12 & 63;
          destination[written++] = 128 | c4 >> 6 & 63;
          destination[written++] = 128 | c4 & 63;
          read++;
        }
      }
      return {
        read,
        written
      };
    }
  };

  // node_modules/cbor2/lib/encoder.js
  var { ENCODED: se } = N;
  var U2 = f.SIMPLE_FLOAT << 5 | o.TWO;
  var h2 = f.SIMPLE_FLOAT << 5 | o.FOUR;
  var B = f.SIMPLE_FLOAT << 5 | o.EIGHT;
  var j = f.SIMPLE_FLOAT << 5 | T.TRUE;
  var P = f.SIMPLE_FLOAT << 5 | T.FALSE;
  var $ = f.SIMPLE_FLOAT << 5 | T.UNDEFINED;
  var q = f.SIMPLE_FLOAT << 5 | T.NULL;
  var z = new TextEncoder();
  var K = new Wtf8Encoder();
  var k = { ...e.defaultOptions, avoidInts: false, cde: false, collapseBigInts: true, dcbor: false, float64: false, flushToZero: false, forceEndian: null, ignoreOriginalEncoding: false, largeNegativeAsBigInt: false, reduceUnsafeNumbers: false, rejectBigInts: false, rejectCustomSimples: false, rejectDuplicateKeys: false, rejectFloats: false, rejectUndefined: false, simplifyNegativeZero: false, sortKeys: null, stringNormalization: null, types: null, wtf8: false };
  var F = { cde: true, ignoreOriginalEncoding: true, sortKeys: f4 };
  var H = { ...F, dcbor: true, largeNegativeAsBigInt: true, reduceUnsafeNumbers: true, rejectCustomSimples: true, rejectDuplicateKeys: true, rejectUndefined: true, simplifyNegativeZero: true, stringNormalization: "NFC" };
  function y2(e2) {
    const n2 = e2 < 0;
    return typeof e2 == "bigint" ? [n2 ? -e2 - 1n : e2, n2] : [n2 ? -e2 - 1 : e2, n2];
  }
  function T2(e2, n2, t3) {
    if (t3.rejectFloats) throw new Error(`Attempt to encode an unwanted floating point number: ${e2}`);
    if (isNaN(e2)) n2.writeUint8(U2), n2.writeUint16(32256);
    else if (!t3.float64 && Math.fround(e2) === e2) {
      const r2 = s3(e2);
      r2 === null ? (n2.writeUint8(h2), n2.writeFloat32(e2)) : (n2.writeUint8(U2), n2.writeUint16(r2));
    } else n2.writeUint8(B), n2.writeFloat64(e2);
  }
  function a(e2, n2, t3) {
    const [r2, i3] = y2(e2);
    if (i3 && t3) throw new TypeError(`Negative size: ${e2}`);
    t3 ?? (t3 = i3 ? f.NEG_INT : f.POS_INT), t3 <<= 5, r2 < 24 ? n2.writeUint8(t3 | r2) : r2 <= 255 ? (n2.writeUint8(t3 | o.ONE), n2.writeUint8(r2)) : r2 <= 65535 ? (n2.writeUint8(t3 | o.TWO), n2.writeUint16(r2)) : r2 <= 4294967295 ? (n2.writeUint8(t3 | o.FOUR), n2.writeUint32(r2)) : (n2.writeUint8(t3 | o.EIGHT), n2.writeBigUint64(BigInt(r2)));
  }
  function p2(e2, n2, t3) {
    typeof e2 == "number" ? a(e2, n2, f.TAG) : typeof e2 == "object" && !t3.ignoreOriginalEncoding && N.ENCODED in e2 ? n2.write(e2[N.ENCODED]) : e2 <= Number.MAX_SAFE_INTEGER ? a(Number(e2), n2, f.TAG) : (n2.writeUint8(f.TAG << 5 | o.EIGHT), n2.writeBigUint64(BigInt(e2)));
  }
  function N2(e2, n2, t3) {
    const [r2, i3] = y2(e2);
    if (t3.collapseBigInts && (!t3.largeNegativeAsBigInt || e2 >= -0x8000000000000000n)) {
      if (r2 <= 0xffffffffn) {
        a(Number(e2), n2);
        return;
      }
      if (r2 <= 0xffffffffffffffffn) {
        const E2 = (i3 ? f.NEG_INT : f.POS_INT) << 5;
        n2.writeUint8(E2 | o.EIGHT), n2.writeBigUint64(r2);
        return;
      }
    }
    if (t3.rejectBigInts) throw new Error(`Attempt to encode unwanted bigint: ${e2}`);
    const o5 = i3 ? I.NEG_BIGINT : I.POS_BIGINT, c4 = r2.toString(16), s4 = c4.length % 2 ? "0" : "";
    p2(o5, n2, t3);
    const u2 = b(s4 + c4);
    a(u2.length, n2, f.BYTE_STRING), n2.write(u2);
  }
  function Y(e2, n2, t3) {
    t3.flushToZero && (e2 = i2(e2)), Object.is(e2, -0) ? t3.simplifyNegativeZero ? t3.avoidInts ? T2(0, n2, t3) : a(0, n2) : T2(e2, n2, t3) : !t3.avoidInts && Number.isSafeInteger(e2) ? a(e2, n2) : t3.reduceUnsafeNumbers && Math.floor(e2) === e2 && e2 >= S.MIN && e2 <= S.MAX ? N2(BigInt(e2), n2, t3) : T2(e2, n2, t3);
  }
  function Z(e2, n2, t3) {
    const r2 = t3.stringNormalization ? e2.normalize(t3.stringNormalization) : e2;
    if (t3.wtf8 && !e2.isWellFormed()) {
      const i3 = K.encode(r2);
      p2(I.WTF8, n2, t3), a(i3.length, n2, f.BYTE_STRING), n2.write(i3);
    } else {
      const i3 = z.encode(r2);
      a(i3.length, n2, f.UTF8_STRING), n2.write(i3);
    }
  }
  function J(e2, n2, t3) {
    const r2 = e2;
    R2(r2, r2.length, f.ARRAY, n2, t3);
    for (const i3 of r2) g2(i3, n2, t3);
  }
  function V(e2, n2) {
    a(e2.length, n2, f.BYTE_STRING), n2.write(e2);
  }
  var b2 = new s2();
  b2.registerEncoder(Array, J), b2.registerEncoder(Uint8Array, V);
  function ce(e2, n2) {
    return b2.registerEncoder(e2, n2);
  }
  function R2(e2, n2, t3, r2, i3) {
    const o5 = s(e2);
    o5 && !i3.ignoreOriginalEncoding ? r2.write(o5) : a(n2, r2, t3);
  }
  function X(e2, n2, t3) {
    if (e2 === null) {
      n2.writeUint8(q);
      return;
    }
    if (!t3.ignoreOriginalEncoding && N.ENCODED in e2) {
      n2.write(e2[N.ENCODED]);
      return;
    }
    const r2 = e2.constructor;
    if (r2) {
      const o5 = t3.types?.get(r2) ?? b2.get(r2);
      if (o5) {
        const c4 = o5(e2, n2, t3);
        if (c4 !== void 0) {
          if (!Array.isArray(c4) || c4.length !== 2) throw new Error("Invalid encoder return value");
          (typeof c4[0] == "bigint" || isFinite(Number(c4[0]))) && p2(c4[0], n2, t3), g2(c4[1], n2, t3);
        }
        return;
      }
    }
    if (typeof e2.toCBOR == "function") {
      const o5 = e2.toCBOR(n2, t3);
      o5 && ((typeof o5[0] == "bigint" || isFinite(Number(o5[0]))) && p2(o5[0], n2, t3), g2(o5[1], n2, t3));
      return;
    }
    if (typeof e2.toJSON == "function") {
      g2(e2.toJSON(), n2, t3);
      return;
    }
    const i3 = Object.entries(e2).map((o5) => [o5[0], o5[1], Q(o5[0], t3)]);
    t3.sortKeys && i3.sort(t3.sortKeys), R2(e2, i3.length, f.MAP, n2, t3);
    for (const [o5, c4, s4] of i3) n2.write(s4), g2(c4, n2, t3);
  }
  function g2(e2, n2, t3) {
    switch (typeof e2) {
      case "number":
        Y(e2, n2, t3);
        break;
      case "bigint":
        N2(e2, n2, t3);
        break;
      case "string":
        Z(e2, n2, t3);
        break;
      case "boolean":
        n2.writeUint8(e2 ? j : P);
        break;
      case "undefined":
        if (t3.rejectUndefined) throw new Error("Attempt to encode unwanted undefined.");
        n2.writeUint8($);
        break;
      case "object":
        X(e2, n2, t3);
        break;
      case "symbol":
        throw new TypeError(`Unknown symbol: ${e2.toString()}`);
      default:
        throw new TypeError(`Unknown type: ${typeof e2}, ${String(e2)}`);
    }
  }
  function Q(e2, n2 = {}) {
    const t3 = { ...k };
    n2.dcbor ? Object.assign(t3, H) : n2.cde && Object.assign(t3, F), Object.assign(t3, n2);
    const r2 = new e(t3);
    return g2(e2, r2, t3), r2.read();
  }
  function de(e2, n2, t3 = f.POS_INT) {
    n2 || (n2 = "f");
    const r2 = { ...k, collapseBigInts: false, chunkSize: 10, simplifyNegativeZero: false }, i3 = new e(r2), o5 = Number(e2);
    function c4(s4) {
      if (Object.is(e2, -0)) throw new Error("Invalid integer: -0");
      const [u2, E2] = y2(e2);
      if (E2 && t3 !== f.POS_INT) throw new Error("Invalid major type combination");
      const w3 = typeof s4 == "number" && isFinite(s4);
      if (w3 && !Number.isSafeInteger(o5)) throw new TypeError(`Unsafe number for ${n2}: ${e2}`);
      if (u2 > s4) throw new TypeError(`Undersized encoding ${n2} for: ${e2}`);
      const A4 = (E2 ? f.NEG_INT : t3) << 5;
      return w3 ? [A4, Number(u2)] : [A4, u2];
    }
    switch (n2) {
      case "bigint":
        if (Object.is(e2, -0)) throw new TypeError("Invalid bigint: -0");
        e2 = BigInt(e2), N2(e2, i3, r2);
        break;
      case "f":
        T2(o5, i3, r2);
        break;
      case "f16": {
        const s4 = s3(o5);
        if (s4 === null) throw new TypeError(`Invalid f16: ${e2}`);
        i3.writeUint8(U2), i3.writeUint16(s4);
        break;
      }
      case "f32":
        if (!isNaN(o5) && Math.fround(o5) !== o5) throw new TypeError(`Invalid f32: ${e2}`);
        i3.writeUint8(h2), i3.writeFloat32(o5);
        break;
      case "f64":
        i3.writeUint8(B), i3.writeFloat64(o5);
        break;
      case "i":
        if (Object.is(e2, -0)) throw new Error("Invalid integer: -0");
        if (Number.isSafeInteger(o5)) a(o5, i3, e2 < 0 ? void 0 : t3);
        else {
          const [s4, u2] = c4(1 / 0);
          u2 > 0xffffffffffffffffn ? (e2 = BigInt(e2), N2(e2, i3, r2)) : (i3.writeUint8(s4 | o.EIGHT), i3.writeBigUint64(BigInt(u2)));
        }
        break;
      case "i0": {
        const [s4, u2] = c4(23);
        i3.writeUint8(s4 | u2);
        break;
      }
      case "i8": {
        const [s4, u2] = c4(255);
        i3.writeUint8(s4 | o.ONE), i3.writeUint8(u2);
        break;
      }
      case "i16": {
        const [s4, u2] = c4(65535);
        i3.writeUint8(s4 | o.TWO), i3.writeUint16(u2);
        break;
      }
      case "i32": {
        const [s4, u2] = c4(4294967295);
        i3.writeUint8(s4 | o.FOUR), i3.writeUint32(u2);
        break;
      }
      case "i64": {
        const [s4, u2] = c4(0xffffffffffffffffn);
        i3.writeUint8(s4 | o.EIGHT), i3.writeBigUint64(BigInt(u2));
        break;
      }
      default:
        throw new TypeError(`Invalid number encoding: "${n2}"`);
    }
    return d(e2, i3.read());
  }

  // node_modules/cbor2/lib/options.js
  var o3 = ((e2) => (e2[e2.NEVER = -1] = "NEVER", e2[e2.PREFERRED = 0] = "PREFERRED", e2[e2.ALWAYS = 1] = "ALWAYS", e2))(o3 || {});

  // node_modules/cbor2/lib/simple.js
  var _t2 = class _t2 {
    constructor(e2) {
      __publicField(this, "value");
      this.value = e2;
    }
    static create(e2) {
      return _t2.KnownSimple.has(e2) ? _t2.KnownSimple.get(e2) : new _t2(e2);
    }
    toCBOR(e2, i3) {
      if (i3.rejectCustomSimples) throw new Error(`Cannot encode non-standard Simple value: ${this.value}`);
      a(this.value, e2, f.SIMPLE_FLOAT);
    }
    toString() {
      return `simple(${this.value})`;
    }
    decode() {
      return _t2.KnownSimple.has(this.value) ? _t2.KnownSimple.get(this.value) : this;
    }
    [Symbol.for("nodejs.util.inspect.custom")](e2, i3, r2) {
      return `simple(${r2(this.value, i3)})`;
    }
  };
  __publicField(_t2, "KnownSimple", /* @__PURE__ */ new Map([[T.FALSE, false], [T.TRUE, true], [T.NULL, null], [T.UNDEFINED, void 0]]));
  var t2 = _t2;

  // node_modules/cbor2/lib/decodeStream.js
  var p3 = new TextDecoder("utf8", { fatal: true, ignoreBOM: true });
  var _t3, _r2, _e4, _i3, _y_instances, n_fn2, a_fn, s_fn;
  var _y = class _y {
    constructor(t3, r2) {
      __privateAdd(this, _y_instances);
      __privateAdd(this, _t3);
      __privateAdd(this, _r2);
      __privateAdd(this, _e4, 0);
      __privateAdd(this, _i3);
      if (__privateSet(this, _i3, { ..._y.defaultOptions, ...r2 }), typeof t3 == "string") switch (__privateGet(this, _i3).encoding) {
        case "hex":
          __privateSet(this, _t3, b(t3));
          break;
        case "base64":
          __privateSet(this, _t3, y(t3));
          break;
        default:
          throw new TypeError(`Encoding not implemented: "${__privateGet(this, _i3).encoding}"`);
      }
      else __privateSet(this, _t3, t3);
      __privateSet(this, _r2, new DataView(__privateGet(this, _t3).buffer, __privateGet(this, _t3).byteOffset, __privateGet(this, _t3).byteLength));
    }
    toHere(t3) {
      return R(__privateGet(this, _t3), t3, __privateGet(this, _e4));
    }
    *[Symbol.iterator]() {
      if (yield* __privateMethod(this, _y_instances, n_fn2).call(this, 0), __privateGet(this, _e4) !== __privateGet(this, _t3).length) throw new Error("Extra data in input");
    }
    *seq() {
      for (; __privateGet(this, _e4) < __privateGet(this, _t3).length; ) yield* __privateMethod(this, _y_instances, n_fn2).call(this, 0);
    }
  };
  _t3 = new WeakMap();
  _r2 = new WeakMap();
  _e4 = new WeakMap();
  _i3 = new WeakMap();
  _y_instances = new WeakSet();
  n_fn2 = function* (t3) {
    if (t3++ > __privateGet(this, _i3).maxDepth) throw new Error(`Maximum depth ${__privateGet(this, _i3).maxDepth} exceeded`);
    const r2 = __privateGet(this, _e4), c4 = __privateGet(this, _r2).getUint8(__privateWrapper(this, _e4)._++), i3 = c4 >> 5, n2 = c4 & 31;
    let e2 = n2, f6 = false, a3 = 0;
    switch (n2) {
      case o.ONE:
        if (a3 = 1, e2 = __privateGet(this, _r2).getUint8(__privateGet(this, _e4)), i3 === f.SIMPLE_FLOAT) {
          if (e2 < 32) throw new Error(`Invalid simple encoding in extra byte: ${e2}`);
          f6 = true;
        } else if (__privateGet(this, _i3).requirePreferred && e2 < 24) throw new Error(`Unexpectedly long integer encoding (1) for ${e2}`);
        break;
      case o.TWO:
        if (a3 = 2, i3 === f.SIMPLE_FLOAT) e2 = o2(__privateGet(this, _t3), __privateGet(this, _e4));
        else if (e2 = __privateGet(this, _r2).getUint16(__privateGet(this, _e4), false), __privateGet(this, _i3).requirePreferred && e2 <= 255) throw new Error(`Unexpectedly long integer encoding (2) for ${e2}`);
        break;
      case o.FOUR:
        if (a3 = 4, i3 === f.SIMPLE_FLOAT) e2 = __privateGet(this, _r2).getFloat32(__privateGet(this, _e4), false);
        else if (e2 = __privateGet(this, _r2).getUint32(__privateGet(this, _e4), false), __privateGet(this, _i3).requirePreferred && e2 <= 65535) throw new Error(`Unexpectedly long integer encoding (4) for ${e2}`);
        break;
      case o.EIGHT: {
        if (a3 = 8, i3 === f.SIMPLE_FLOAT) e2 = __privateGet(this, _r2).getFloat64(__privateGet(this, _e4), false);
        else if (e2 = __privateGet(this, _r2).getBigUint64(__privateGet(this, _e4), false), e2 <= Number.MAX_SAFE_INTEGER && (e2 = Number(e2)), __privateGet(this, _i3).requirePreferred && e2 <= 4294967295) throw new Error(`Unexpectedly long integer encoding (8) for ${e2}`);
        break;
      }
      case 28:
      case 29:
      case 30:
        throw new Error(`Additional info not implemented: ${n2}`);
      case o.INDEFINITE:
        switch (i3) {
          case f.POS_INT:
          case f.NEG_INT:
          case f.TAG:
            throw new Error(`Invalid indefinite encoding for MT ${i3}`);
          case f.SIMPLE_FLOAT:
            yield [i3, n2, N.BREAK, r2, 0];
            return;
        }
        e2 = 1 / 0;
        break;
      default:
        f6 = true;
    }
    switch (__privateSet(this, _e4, __privateGet(this, _e4) + a3), i3) {
      case f.POS_INT:
        yield [i3, n2, e2, r2, a3];
        break;
      case f.NEG_INT:
        yield [i3, n2, typeof e2 == "bigint" ? -1n - e2 : -1 - Number(e2), r2, a3];
        break;
      case f.BYTE_STRING:
        e2 === 1 / 0 ? yield* __privateMethod(this, _y_instances, s_fn).call(this, i3, t3, r2) : yield [i3, n2, __privateMethod(this, _y_instances, a_fn).call(this, e2), r2, e2];
        break;
      case f.UTF8_STRING:
        e2 === 1 / 0 ? yield* __privateMethod(this, _y_instances, s_fn).call(this, i3, t3, r2) : yield [i3, n2, p3.decode(__privateMethod(this, _y_instances, a_fn).call(this, e2)), r2, e2];
        break;
      case f.ARRAY:
        if (e2 === 1 / 0) yield* __privateMethod(this, _y_instances, s_fn).call(this, i3, t3, r2, false);
        else {
          const o5 = Number(e2);
          yield [i3, n2, o5, r2, a3];
          for (let h4 = 0; h4 < o5; h4++) yield* __privateMethod(this, _y_instances, n_fn2).call(this, t3 + 1);
        }
        break;
      case f.MAP:
        if (e2 === 1 / 0) yield* __privateMethod(this, _y_instances, s_fn).call(this, i3, t3, r2, false);
        else {
          const o5 = Number(e2);
          yield [i3, n2, o5, r2, a3];
          for (let h4 = 0; h4 < o5; h4++) yield* __privateMethod(this, _y_instances, n_fn2).call(this, t3), yield* __privateMethod(this, _y_instances, n_fn2).call(this, t3);
        }
        break;
      case f.TAG:
        yield [i3, n2, e2, r2, a3], yield* __privateMethod(this, _y_instances, n_fn2).call(this, t3);
        break;
      case f.SIMPLE_FLOAT: {
        const o5 = e2;
        f6 && (e2 = t2.create(Number(e2))), yield [i3, n2, e2, r2, o5];
        break;
      }
    }
  };
  a_fn = function(t3) {
    const r2 = R(__privateGet(this, _t3), __privateGet(this, _e4), __privateSet(this, _e4, __privateGet(this, _e4) + t3));
    if (r2.length !== t3) throw new Error(`Unexpected end of stream reading ${t3} bytes, got ${r2.length}`);
    return r2;
  };
  s_fn = function* (t3, r2, c4, i3 = true) {
    for (yield [t3, o.INDEFINITE, 1 / 0, c4, 1 / 0]; ; ) {
      const n2 = __privateMethod(this, _y_instances, n_fn2).call(this, r2), e2 = n2.next(), [f6, a3, o5] = e2.value;
      if (o5 === N.BREAK) {
        yield e2.value, n2.next();
        return;
      }
      if (i3) {
        if (f6 !== t3) throw new Error(`Unmatched major type.  Expected ${t3}, got ${f6}.`);
        if (a3 === o.INDEFINITE) throw new Error("New stream started in typed stream");
      }
      yield e2.value, yield* n2;
    }
  };
  __publicField(_y, "defaultOptions", { maxDepth: 1024, encoding: "hex", requirePreferred: false });
  var y3 = _y;

  // node_modules/cbor2/lib/container.js
  var v = /* @__PURE__ */ new Map([[o.ZERO, 1], [o.ONE, 2], [o.TWO, 3], [o.FOUR, 5], [o.EIGHT, 9]]);
  var A2 = new Uint8Array(0);
  function k2(d5, r2) {
    return !r2.boxed && !r2.preferMap && d5.every(([i3]) => typeof i3 == "string") ? Object.fromEntries(d5) : new Map(d5);
  }
  var _e5, _t4, _w_instances, r_fn;
  var _w = class _w {
    constructor(r2, i3, e2, t3) {
      __privateAdd(this, _w_instances);
      __publicField(this, "parent");
      __publicField(this, "mt");
      __publicField(this, "ai");
      __publicField(this, "left");
      __publicField(this, "offset");
      __publicField(this, "count", 0);
      __publicField(this, "children", []);
      __publicField(this, "depth", 0);
      __privateAdd(this, _e5);
      __privateAdd(this, _t4, null);
      if ([this.mt, this.ai, , this.offset] = r2, this.left = i3, this.parent = e2, __privateSet(this, _e5, t3), e2 && (this.depth = e2.depth + 1), this.mt === f.MAP && (__privateGet(this, _e5).sortKeys || __privateGet(this, _e5).rejectDuplicateKeys) && __privateSet(this, _t4, []), __privateGet(this, _e5).rejectStreaming && this.ai === o.INDEFINITE) throw new Error("Streaming not supported");
    }
    get isStreaming() {
      return this.left === 1 / 0;
    }
    get done() {
      return this.left === 0;
    }
    static create(r2, i3, e2, t3) {
      const [s4, l6, n2, c4] = r2;
      switch (s4) {
        case f.POS_INT:
        case f.NEG_INT: {
          if (e2.rejectInts) throw new Error(`Unexpected integer: ${n2}`);
          if (e2.rejectLargeNegatives && n2 < -0x8000000000000000n) throw new Error(`Invalid 65bit negative number: ${n2}`);
          let o5 = n2;
          return e2.convertUnsafeIntsToFloat && o5 >= S.MIN && o5 <= S.MAX && (o5 = Number(n2)), e2.boxed ? d(o5, t3.toHere(c4)) : o5;
        }
        case f.SIMPLE_FLOAT:
          if (l6 > o.ONE) {
            if (e2.rejectFloats) throw new Error(`Decoding unwanted floating point number: ${n2}`);
            if (e2.rejectNegativeZero && Object.is(n2, -0)) throw new Error("Decoding negative zero");
            if (e2.rejectLongLoundNaN && isNaN(n2)) {
              const o5 = t3.toHere(c4);
              if (o5.length !== 3 || o5[1] !== 126 || o5[2] !== 0) throw new Error(`Invalid NaN encoding: "${A(o5)}"`);
            }
            if (e2.rejectSubnormals && l3(t3.toHere(c4 + 1)), e2.rejectLongFloats) {
              const o5 = Q(n2, { chunkSize: 9, reduceUnsafeNumbers: e2.rejectUnsafeFloatInts });
              if (o5[0] >> 5 !== s4) throw new Error(`Should have been encoded as int, not float: ${n2}`);
              if (o5.length < v.get(l6)) throw new Error(`Number should have been encoded shorter: ${n2}`);
            }
            if (typeof n2 == "number" && e2.boxed) return d(n2, t3.toHere(c4));
          } else {
            if (e2.rejectSimple && n2 instanceof t2) throw new Error(`Invalid simple value: ${n2}`);
            if (e2.rejectUndefined && n2 === void 0) throw new Error("Unexpected undefined");
          }
          return n2;
        case f.BYTE_STRING:
        case f.UTF8_STRING:
          if (n2 === 1 / 0) return new e2.ParentType(r2, 1 / 0, i3, e2);
          if (e2.rejectStringsNotNormalizedAs && typeof n2 == "string") {
            const o5 = n2.normalize(e2.rejectStringsNotNormalizedAs);
            if (n2 !== o5) throw new Error(`String not normalized as "${e2.rejectStringsNotNormalizedAs}", got [${U(n2)}] instead of [${U(o5)}]`);
          }
          return e2.boxed ? d(n2, t3.toHere(c4)) : n2;
        case f.ARRAY:
          return new e2.ParentType(r2, n2, i3, e2);
        case f.MAP:
          return new e2.ParentType(r2, n2 * 2, i3, e2);
        case f.TAG: {
          const o5 = new e2.ParentType(r2, 1, i3, e2);
          return o5.children = new i(n2), o5;
        }
      }
      throw new TypeError(`Invalid major type: ${s4}`);
    }
    static decodeToEncodeOpts(r2) {
      return { ...k, avoidInts: r2.rejectInts, float64: !r2.rejectLongFloats, flushToZero: r2.rejectSubnormals, largeNegativeAsBigInt: r2.rejectLargeNegatives, sortKeys: r2.sortKeys };
    }
    push(r2, i3, e2) {
      if (this.children.push(r2), __privateGet(this, _t4)) {
        const t3 = f2(r2) || i3.toHere(e2);
        __privateGet(this, _t4).push(t3);
      }
      return --this.left;
    }
    replaceLast(r2, i3, e2) {
      let t3, s4 = -1 / 0;
      if (this.children instanceof i ? (s4 = 0, t3 = this.children.contents, this.children.contents = r2) : (s4 = this.children.length - 1, t3 = this.children[s4], this.children[s4] = r2), __privateGet(this, _t4)) {
        const l6 = f2(r2) || e2.toHere(i3.offset);
        __privateGet(this, _t4)[s4] = l6;
      }
      return t3;
    }
    convert(r2) {
      let i3;
      switch (this.mt) {
        case f.ARRAY:
          i3 = this.children;
          break;
        case f.MAP: {
          const e2 = __privateMethod(this, _w_instances, r_fn).call(this);
          if (__privateGet(this, _e5).sortKeys) {
            let t3;
            for (const s4 of e2) {
              if (t3 && __privateGet(this, _e5).sortKeys(t3, s4) >= 0) throw new Error(`Duplicate or out of order key: "0x${s4[2]}"`);
              t3 = s4;
            }
          } else if (__privateGet(this, _e5).rejectDuplicateKeys) {
            const t3 = /* @__PURE__ */ new Set();
            for (const [s4, l6, n2] of e2) {
              const c4 = A(n2);
              if (t3.has(c4)) throw new Error(`Duplicate key: "0x${c4}"`);
              t3.add(c4);
            }
          }
          i3 = __privateGet(this, _e5).createObject(e2, __privateGet(this, _e5));
          break;
        }
        case f.BYTE_STRING:
          return d2(this.children);
        case f.UTF8_STRING: {
          const e2 = this.children.join("");
          i3 = __privateGet(this, _e5).boxed ? d(e2, r2.toHere(this.offset)) : e2;
          break;
        }
        case f.TAG:
          i3 = this.children.decode(__privateGet(this, _e5));
          break;
        default:
          throw new TypeError(`Invalid mt on convert: ${this.mt}`);
      }
      return __privateGet(this, _e5).saveOriginal && i3 && typeof i3 == "object" && u(i3, r2.toHere(this.offset)), i3;
    }
  };
  _e5 = new WeakMap();
  _t4 = new WeakMap();
  _w_instances = new WeakSet();
  r_fn = function() {
    const r2 = this.children, i3 = r2.length;
    if (i3 % 2) throw new Error("Missing map value");
    const e2 = new Array(i3 / 2);
    if (__privateGet(this, _t4)) for (let t3 = 0; t3 < i3; t3 += 2) e2[t3 >> 1] = [r2[t3], r2[t3 + 1], __privateGet(this, _t4)[t3]];
    else for (let t3 = 0; t3 < i3; t3 += 2) e2[t3 >> 1] = [r2[t3], r2[t3 + 1], A2];
    return e2;
  };
  __publicField(_w, "defaultDecodeOptions", { ...y3.defaultOptions, ParentType: _w, boxed: false, cde: false, dcbor: false, diagnosticSizes: o3.PREFERRED, convertUnsafeIntsToFloat: false, createObject: k2, pretty: false, preferMap: false, rejectLargeNegatives: false, rejectBigInts: false, rejectDuplicateKeys: false, rejectFloats: false, rejectInts: false, rejectLongLoundNaN: false, rejectLongFloats: false, rejectNegativeZero: false, rejectSimple: false, rejectStreaming: false, rejectStringsNotNormalizedAs: null, rejectSubnormals: false, rejectUndefined: false, rejectUnsafeFloatInts: false, saveOriginal: false, sortKeys: null, tags: null });
  __publicField(_w, "cdeDecodeOptions", { cde: true, rejectStreaming: true, requirePreferred: true, sortKeys: f4 });
  __publicField(_w, "dcborDecodeOptions", { ..._w.cdeDecodeOptions, dcbor: true, convertUnsafeIntsToFloat: true, rejectDuplicateKeys: true, rejectLargeNegatives: true, rejectLongLoundNaN: true, rejectLongFloats: true, rejectNegativeZero: true, rejectSimple: true, rejectUndefined: true, rejectUnsafeFloatInts: true, rejectStringsNotNormalizedAs: "NFC" });
  var w = _w;

  // node_modules/cbor2/lib/diagnostic.js
  var O = "  ";
  var y4 = new TextEncoder();
  var g3 = class extends w {
    constructor() {
      super(...arguments);
      __publicField(this, "close", "");
      __publicField(this, "quote", '"');
    }
    get isEmptyStream() {
      return (this.mt === f.UTF8_STRING || this.mt === f.BYTE_STRING) && this.count === 0;
    }
  };
  function a2(m2, l6, n2, p4) {
    let t3 = "";
    if (l6 === o.INDEFINITE) t3 += "_";
    else {
      if (p4.diagnosticSizes === o3.NEVER) return "";
      {
        let r2 = p4.diagnosticSizes === o3.ALWAYS;
        if (!r2) {
          let e2 = o.ZERO;
          if (Object.is(n2, -0)) e2 = o.TWO;
          else if (m2 === f.POS_INT || m2 === f.NEG_INT) {
            const T4 = n2 < 0, u2 = typeof n2 == "bigint" ? 1n : 1, o5 = T4 ? -n2 - u2 : n2;
            o5 <= 23 ? e2 = Number(o5) : o5 <= 255 ? e2 = o.ONE : o5 <= 65535 ? e2 = o.TWO : o5 <= 4294967295 ? e2 = o.FOUR : e2 = o.EIGHT;
          } else isFinite(n2) ? Math.fround(n2) === n2 ? s3(n2) == null ? e2 = o.FOUR : e2 = o.TWO : e2 = o.EIGHT : e2 = o.TWO;
          r2 = e2 !== l6;
        }
        r2 && (t3 += "_", l6 < o.ONE ? t3 += "i" : t3 += String(l6 - 24));
      }
    }
    return t3;
  }
  function M(m2, l6) {
    const n2 = { ...w.defaultDecodeOptions, ...l6, ParentType: g3 }, p4 = new y3(m2, n2);
    let t3, r2, e2 = "";
    for (const T4 of p4) {
      const [u2, o5, i3] = T4;
      switch (t3 && (t3.count > 0 && i3 !== N.BREAK && (t3.mt === f.MAP && t3.count % 2 ? e2 += ": " : (e2 += ",", n2.pretty || (e2 += " "))), n2.pretty && (t3.mt !== f.MAP || t3.count % 2 === 0) && (e2 += `
${O.repeat(t3.depth + 1)}`)), r2 = w.create(T4, t3, n2, p4), u2) {
        case f.POS_INT:
        case f.NEG_INT:
          e2 += String(i3), e2 += a2(u2, o5, i3, n2);
          break;
        case f.SIMPLE_FLOAT:
          if (i3 !== N.BREAK) if (typeof i3 == "number") {
            const c4 = Object.is(i3, -0) ? "-0.0" : String(i3);
            e2 += c4, isFinite(i3) && !/[.e]/.test(c4) && (e2 += ".0"), e2 += a2(u2, o5, i3, n2);
          } else i3 instanceof t2 ? (e2 += "simple(", e2 += String(i3.value), e2 += a2(f.POS_INT, o5, i3.value, n2), e2 += ")") : e2 += String(i3);
          break;
        case f.BYTE_STRING:
          i3 === 1 / 0 ? (e2 += "(_ ", r2.close = ")", r2.quote = "'") : (e2 += "h'", e2 += A(i3), e2 += "'", e2 += a2(f.POS_INT, o5, i3.length, n2));
          break;
        case f.UTF8_STRING:
          i3 === 1 / 0 ? (e2 += "(_ ", r2.close = ")") : (e2 += JSON.stringify(i3), e2 += a2(f.POS_INT, o5, y4.encode(i3).length, n2));
          break;
        case f.ARRAY: {
          e2 += "[";
          const c4 = a2(f.POS_INT, o5, i3, n2);
          e2 += c4, c4 && (e2 += " "), n2.pretty && i3 ? r2.close = `
${O.repeat(r2.depth)}]` : r2.close = "]";
          break;
        }
        case f.MAP: {
          e2 += "{";
          const c4 = a2(f.POS_INT, o5, i3, n2);
          e2 += c4, c4 && (e2 += " "), n2.pretty && i3 ? r2.close = `
${O.repeat(r2.depth)}}` : r2.close = "}";
          break;
        }
        case f.TAG:
          e2 += String(i3), e2 += a2(f.POS_INT, o5, i3, n2), e2 += "(", r2.close = ")";
          break;
      }
      if (r2 === N.BREAK) if (t3?.isStreaming) t3.left = 0;
      else throw new Error("Unexpected BREAK");
      else t3 && (t3.count++, t3.left--);
      for (r2 instanceof g3 && (t3 = r2); t3?.done; ) {
        if (t3.isEmptyStream) e2 = e2.slice(0, -3), e2 += `${t3.quote}${t3.quote}_`;
        else {
          if (t3.mt === f.MAP && t3.count % 2 !== 0) throw new Error(`Odd streaming map size: ${t3.count}`);
          e2 += t3.close;
        }
        t3 = t3.parent;
      }
    }
    return e2;
  }

  // node_modules/cbor2/lib/comment.js
  var H2 = new TextDecoder();
  var _a2, _b;
  var A3 = class extends (_b = w, _a2 = N.ENCODED, _b) {
    constructor(a3, f6, e2, n2) {
      super(a3, f6, e2, n2);
      __publicField(this, "depth", 0);
      __publicField(this, "leaf", false);
      __publicField(this, "value");
      __publicField(this, "length");
      __publicField(this, _a2);
      this.parent ? this.depth = this.parent.depth + 1 : this.depth = n2.initialDepth, [, , this.value, , this.length] = a3;
    }
    numBytes() {
      switch (this.ai) {
        case o.ONE:
          return 1;
        case o.TWO:
          return 2;
        case o.FOUR:
          return 4;
        case o.EIGHT:
          return 8;
      }
      return 0;
    }
  };
  function k3(t3) {
    return t3 instanceof A3;
  }
  function O2(t3, a3) {
    return t3 === 1 / 0 ? "Indefinite" : a3 ? `${t3} ${a3}${t3 !== 1 && t3 !== 1n ? "s" : ""}` : String(t3);
  }
  function y5(t3) {
    return "".padStart(t3, " ");
  }
  function x2(t3, a3, f6) {
    let e2 = "";
    e2 += y5(t3.depth * 2);
    const n2 = f2(t3);
    e2 += A(n2.subarray(0, 1));
    const r2 = t3.numBytes();
    r2 && (e2 += " ", e2 += A(n2.subarray(1, r2 + 1))), e2 = e2.padEnd(a3.minCol + 1, " "), e2 += "-- ", f6 !== void 0 && (e2 += y5(t3.depth * 2), f6 !== "" && (e2 += `[${f6}] `));
    let p4 = false;
    const [s4] = t3.children;
    switch (t3.mt) {
      case f.POS_INT:
        e2 += `Unsigned: ${s4}`, typeof s4 == "bigint" && (e2 += "n");
        break;
      case f.NEG_INT:
        e2 += `Negative: ${s4}`, typeof s4 == "bigint" && (e2 += "n");
        break;
      case f.BYTE_STRING:
        e2 += `Bytes (Length: ${O2(t3.length)})`;
        break;
      case f.UTF8_STRING:
        e2 += `UTF8 (Length: ${O2(t3.length)})`, t3.length !== 1 / 0 && (e2 += `: ${JSON.stringify(s4)}`);
        break;
      case f.ARRAY:
        e2 += `Array (Length: ${O2(t3.value, "item")})`;
        break;
      case f.MAP:
        e2 += `Map (Length: ${O2(t3.value, "pair")})`;
        break;
      case f.TAG: {
        e2 += `Tag #${t3.value}`;
        const o5 = t3.children, [m2] = o5.contents.children, i3 = new i(o5.tag, m2);
        u(i3, n2);
        const l6 = i3.comment(a3, t3.depth);
        l6 && (e2 += ": ", e2 += l6), p4 || (p4 = i3.noChildren);
        break;
      }
      case f.SIMPLE_FLOAT:
        s4 === N.BREAK ? e2 += "BREAK" : t3.ai > o.ONE ? Object.is(s4, -0) ? e2 += "Float: -0" : e2 += `Float: ${s4}` : (e2 += "Simple: ", s4 instanceof t2 ? e2 += s4.value : e2 += s4);
        break;
    }
    if (!p4) if (t3.leaf) {
      if (e2 += `
`, n2.length > r2 + 1) {
        const o5 = y5((t3.depth + 1) * 2), m2 = f3(n2);
        if (m2?.length) {
          m2.sort((l6, c4) => {
            const g4 = l6[0] - c4[0];
            return g4 || c4[1] - l6[1];
          });
          let i3 = 0;
          for (const [l6, c4, g4] of m2) if (!(l6 < i3)) {
            if (i3 = l6 + c4, g4 === "<<") {
              e2 += y5(a3.minCol + 1), e2 += "--", e2 += o5, e2 += "<< ";
              const d5 = R(n2, l6, l6 + c4), h4 = f3(d5);
              if (h4) {
                const $3 = h4.findIndex(([w3, D2, v2]) => w3 === 0 && D2 === c4 && v2 === "<<");
                $3 >= 0 && h4.splice($3, 1);
              }
              e2 += M(d5), e2 += ` >>
`, e2 += L(d5, { initialDepth: t3.depth + 1, minCol: a3.minCol, noPrefixHex: true });
              continue;
            } else g4 === "'" && (e2 += y5(a3.minCol + 1), e2 += "--", e2 += o5, e2 += "'", e2 += H2.decode(n2.subarray(l6, l6 + c4)), e2 += `'
`);
            if (l6 > r2) for (let d5 = l6; d5 < l6 + c4; d5 += 8) {
              const h4 = Math.min(d5 + 8, l6 + c4);
              e2 += o5, e2 += A(n2.subarray(d5, h4)), e2 += `
`;
            }
          }
        } else for (let i3 = r2 + 1; i3 < n2.length; i3 += 8) e2 += o5, e2 += A(n2.subarray(i3, i3 + 8)), e2 += `
`;
      }
    } else {
      e2 += `
`;
      let o5 = 0;
      for (const m2 of t3.children) {
        if (k3(m2)) {
          let i3 = String(o5);
          t3.mt === f.MAP ? i3 = o5 % 2 ? `val ${(o5 - 1) / 2}` : `key ${o5 / 2}` : t3.mt === f.TAG && (i3 = ""), e2 += x2(m2, a3, i3);
        }
        o5++;
      }
    }
    return e2;
  }
  var q2 = { ...w.defaultDecodeOptions, initialDepth: 0, noPrefixHex: false, minCol: 0 };
  function L(t3, a3) {
    const f6 = { ...q2, ...a3, ParentType: A3, saveOriginal: true }, e2 = new y3(t3, f6);
    let n2, r2;
    for (const s4 of e2) {
      if (r2 = w.create(s4, n2, f6, e2), s4[2] === N.BREAK) if (n2?.isStreaming) n2.left = 1;
      else throw new Error("Unexpected BREAK");
      if (!k3(r2)) {
        const i3 = new A3(s4, 0, n2, f6);
        i3.leaf = true, i3.children.push(r2), u(i3, e2.toHere(s4[3])), r2 = i3;
      }
      let o5 = (r2.depth + 1) * 2;
      const m2 = r2.numBytes();
      for (m2 && (o5 += 1, o5 += m2 * 2), f6.minCol = Math.max(f6.minCol, o5), n2 && n2.push(r2, e2, s4[3]), n2 = r2; n2?.done; ) r2 = n2, r2.leaf || u(r2, e2.toHere(r2.offset)), { parent: n2 } = n2;
    }
    a3 && (a3.minCol = f6.minCol);
    let p4 = f6.noPrefixHex ? "" : `0x${A(e2.toHere(0))}
`;
    return p4 += x2(r2, f6), p4;
  }

  // node_modules/cbor2/lib/types.js
  var S2 = !h();
  function O3(e2) {
    if (typeof e2 == "object" && e2) {
      if (e2.constructor !== Number) throw new Error(`Expected number: ${e2}`);
    } else if (typeof e2 != "number") throw new Error(`Expected number: ${e2}`);
  }
  function E(e2) {
    if (typeof e2 == "object" && e2) {
      if (e2.constructor !== String) throw new Error(`Expected string: ${e2}`);
    } else if (typeof e2 != "string") throw new Error(`Expected string: ${e2}`);
  }
  function f5(e2) {
    if (!(e2 instanceof Uint8Array)) throw new Error(`Expected Uint8Array: ${e2}`);
  }
  function U3(e2) {
    if (!Array.isArray(e2)) throw new Error(`Expected Array: ${e2}`);
  }
  ce(Map, (e2, r2, n2) => {
    const t3 = [...e2.entries()].map((o5) => [o5[0], o5[1], Q(o5[0], n2)]);
    if (n2.rejectDuplicateKeys) {
      const o5 = /* @__PURE__ */ new Set();
      for (const [d5, u2, y6] of t3) {
        const g4 = A(y6);
        if (o5.has(g4)) throw new Error(`Duplicate map key: 0x${g4}`);
        o5.add(g4);
      }
    }
    n2.sortKeys && t3.sort(n2.sortKeys), R2(e2, e2.size, f.MAP, r2, n2);
    for (const [o5, d5, u2] of t3) r2.write(u2), g2(d5, r2, n2);
  });
  function h3(e2) {
    return E(e2.contents), new Date(e2.contents);
  }
  h3.comment = (e2) => (E(e2.contents), `(String Date) ${new Date(e2.contents).toISOString()}`), i.registerDecoder(I.DATE_STRING, h3);
  function N3(e2) {
    return O3(e2.contents), new Date(e2.contents * 1e3);
  }
  N3.comment = (e2) => (O3(e2.contents), `(Epoch Date) ${new Date(e2.contents * 1e3).toISOString()}`), i.registerDecoder(I.DATE_EPOCH, N3), ce(Date, (e2) => [I.DATE_EPOCH, e2.valueOf() / 1e3]);
  function T3(e2, r2, n2) {
    if (f5(r2.contents), n2.rejectBigInts) throw new Error(`Decoding unwanted big integer: ${r2}(h'${A(r2.contents)}')`);
    if (n2.requirePreferred && r2.contents[0] === 0) throw new Error(`Decoding overly-large bigint: ${r2.tag}(h'${A(r2.contents)})`);
    let t3 = r2.contents.reduce((o5, d5) => o5 << 8n | BigInt(d5), 0n);
    if (e2 && (t3 = -1n - t3), n2.requirePreferred && t3 >= Number.MIN_SAFE_INTEGER && t3 <= Number.MAX_SAFE_INTEGER) throw new Error(`Decoding bigint that could have been int: ${t3}n`);
    return n2.boxed ? d(t3, r2.contents) : t3;
  }
  var _ = T3.bind(null, false);
  var $2 = T3.bind(null, true);
  _.comment = (e2, r2) => `(Positive BigInt) ${T3(false, e2, r2)}n`, $2.comment = (e2, r2) => `(Negative BigInt) ${T3(true, e2, r2)}n`, i.registerDecoder(I.POS_BIGINT, _), i.registerDecoder(I.NEG_BIGINT, $2);
  function D(e2, r2) {
    return f5(e2.contents), e2;
  }
  D.comment = (e2, r2, n2) => {
    f5(e2.contents);
    const t3 = { ...r2, initialDepth: n2 + 2, noPrefixHex: true }, o5 = f2(e2);
    let u2 = 2 ** ((o5[0] & 31) - 24) + 1;
    const y6 = o5[u2] & 31;
    let g4 = A(o5.subarray(u2, ++u2));
    y6 >= 24 && (g4 += " ", g4 += A(o5.subarray(u2, u2 + 2 ** (y6 - 24)))), t3.minCol = Math.max(t3.minCol, (n2 + 1) * 2 + g4.length);
    const p4 = L(e2.contents, t3);
    let I2 = `Embedded CBOR
`;
    return I2 += `${"".padStart((n2 + 1) * 2, " ")}${g4}`.padEnd(t3.minCol + 1, " "), I2 += `-- Bytes (Length: ${e2.contents.length})
`, I2 += p4, I2;
  }, D.noChildren = true, i.registerDecoder(I.CBOR, D), i.registerDecoder(I.URI, (e2) => (E(e2.contents), new URL(e2.contents)), "URI"), ce(URL, (e2) => [I.URI, e2.toString()]), i.registerDecoder(I.BASE64URL, (e2) => (E(e2.contents), x(e2.contents)), "Base64url-encoded"), i.registerDecoder(I.BASE64, (e2) => (E(e2.contents), y(e2.contents)), "Base64-encoded"), i.registerDecoder(35, (e2) => (E(e2.contents), new RegExp(e2.contents)), "RegExp"), i.registerDecoder(21065, (e2) => {
    E(e2.contents);
    const r2 = `^(?:${e2.contents})$`;
    return new RegExp(r2, "u");
  }, "I-RegExp"), i.registerDecoder(I.REGEXP, (e2) => {
    if (U3(e2.contents), e2.contents.length < 1 || e2.contents.length > 2) throw new Error(`Invalid RegExp Array: ${e2.contents}`);
    return new RegExp(e2.contents[0], e2.contents[1]);
  }, "RegExp"), ce(RegExp, (e2) => [I.REGEXP, [e2.source, e2.flags]]), i.registerDecoder(64, (e2) => (f5(e2.contents), e2.contents), "uint8 Typed Array");
  function c2(e2, r2, n2) {
    f5(e2.contents);
    let t3 = e2.contents.length;
    if (t3 % r2.BYTES_PER_ELEMENT !== 0) throw new Error(`Number of bytes must be divisible by ${r2.BYTES_PER_ELEMENT}, got: ${t3}`);
    t3 /= r2.BYTES_PER_ELEMENT;
    const o5 = new r2(t3), d5 = new DataView(e2.contents.buffer, e2.contents.byteOffset, e2.contents.byteLength), u2 = d5[`get${r2.name.replace(/Array/, "")}`].bind(d5);
    for (let y6 = 0; y6 < t3; y6++) o5[y6] = u2(y6 * r2.BYTES_PER_ELEMENT, n2);
    return o5;
  }
  function l4(e2, r2, n2, t3, o5) {
    const d5 = o5.forceEndian ?? S2;
    if (p2(d5 ? r2 : n2, e2, o5), a(t3.byteLength, e2, f.BYTE_STRING), S2 === d5) e2.write(new Uint8Array(t3.buffer, t3.byteOffset, t3.byteLength));
    else {
      const y6 = `write${t3.constructor.name.replace(/Array/, "")}`, g4 = e2[y6].bind(e2);
      for (const p4 of t3) g4(p4, d5);
    }
  }
  i.registerDecoder(65, (e2) => c2(e2, Uint16Array, false), "uint16, big endian, Typed Array"), i.registerDecoder(66, (e2) => c2(e2, Uint32Array, false), "uint32, big endian, Typed Array"), i.registerDecoder(67, (e2) => c2(e2, BigUint64Array, false), "uint64, big endian, Typed Array"), i.registerDecoder(68, (e2) => (f5(e2.contents), new Uint8ClampedArray(e2.contents)), "uint8 Typed Array, clamped arithmetic"), ce(Uint8ClampedArray, (e2) => [68, new Uint8Array(e2.buffer, e2.byteOffset, e2.byteLength)]), i.registerDecoder(69, (e2) => c2(e2, Uint16Array, true), "uint16, little endian, Typed Array"), ce(Uint16Array, (e2, r2, n2) => l4(r2, 69, 65, e2, n2)), i.registerDecoder(70, (e2) => c2(e2, Uint32Array, true), "uint32, little endian, Typed Array"), ce(Uint32Array, (e2, r2, n2) => l4(r2, 70, 66, e2, n2)), i.registerDecoder(71, (e2) => c2(e2, BigUint64Array, true), "uint64, little endian, Typed Array"), ce(BigUint64Array, (e2, r2, n2) => l4(r2, 71, 67, e2, n2)), i.registerDecoder(72, (e2) => (f5(e2.contents), new Int8Array(e2.contents)), "sint8 Typed Array"), ce(Int8Array, (e2) => [72, new Uint8Array(e2.buffer, e2.byteOffset, e2.byteLength)]), i.registerDecoder(73, (e2) => c2(e2, Int16Array, false), "sint16, big endian, Typed Array"), i.registerDecoder(74, (e2) => c2(e2, Int32Array, false), "sint32, big endian, Typed Array"), i.registerDecoder(75, (e2) => c2(e2, BigInt64Array, false), "sint64, big endian, Typed Array"), i.registerDecoder(77, (e2) => c2(e2, Int16Array, true), "sint16, little endian, Typed Array"), ce(Int16Array, (e2, r2, n2) => l4(r2, 77, 73, e2, n2)), i.registerDecoder(78, (e2) => c2(e2, Int32Array, true), "sint32, little endian, Typed Array"), ce(Int32Array, (e2, r2, n2) => l4(r2, 78, 74, e2, n2)), i.registerDecoder(79, (e2) => c2(e2, BigInt64Array, true), "sint64, little endian, Typed Array"), ce(BigInt64Array, (e2, r2, n2) => l4(r2, 79, 75, e2, n2)), i.registerDecoder(81, (e2) => c2(e2, Float32Array, false), "IEEE 754 binary32, big endian, Typed Array"), i.registerDecoder(82, (e2) => c2(e2, Float64Array, false), "IEEE 754 binary64, big endian, Typed Array"), i.registerDecoder(85, (e2) => c2(e2, Float32Array, true), "IEEE 754 binary32, little endian, Typed Array"), ce(Float32Array, (e2, r2, n2) => l4(r2, 85, 81, e2, n2)), i.registerDecoder(86, (e2) => c2(e2, Float64Array, true), "IEEE 754 binary64, big endian, Typed Array"), ce(Float64Array, (e2, r2, n2) => l4(r2, 86, 82, e2, n2)), i.registerDecoder(I.SET, (e2, r2) => {
    if (U3(e2.contents), r2.sortKeys) {
      const n2 = w.decodeToEncodeOpts(r2);
      let t3 = null;
      for (const o5 of e2.contents) {
        const d5 = [o5, void 0, Q(o5, n2)];
        if (t3 && r2.sortKeys(t3, d5) >= 0) throw new Error(`Set items out of order in tag #${I.SET}`);
        t3 = d5;
      }
    }
    return new Set(e2.contents);
  }, "Set"), ce(Set, (e2, r2, n2) => {
    let t3 = [...e2];
    if (n2.sortKeys) {
      const o5 = t3.map((d5) => [d5, void 0, Q(d5, n2)]);
      o5.sort(n2.sortKeys), t3 = o5.map(([d5]) => d5);
    }
    return [I.SET, t3];
  }), i.registerDecoder(I.JSON, (e2) => (E(e2.contents), JSON.parse(e2.contents)), "JSON-encoded");
  function x3(e2) {
    return f5(e2.contents), new Wtf8Decoder().decode(e2.contents);
  }
  x3.comment = (e2) => {
    f5(e2.contents);
    const r2 = new Wtf8Decoder();
    return `(WTF8 string): ${JSON.stringify(r2.decode(e2.contents))}`;
  }, i.registerDecoder(I.WTF8, x3), i.registerDecoder(I.SELF_DESCRIBED, (e2) => e2.contents, "Self-Described"), i.registerDecoder(I.INVALID_16, () => {
    throw new Error(`Tag always invalid: ${I.INVALID_16}`);
  }, "Invalid"), i.registerDecoder(I.INVALID_32, () => {
    throw new Error(`Tag always invalid: ${I.INVALID_32}`);
  }, "Invalid"), i.registerDecoder(I.INVALID_64, () => {
    throw new Error(`Tag always invalid: ${I.INVALID_64}`);
  }, "Invalid");
  function w2(e2) {
    throw new Error(`Encoding ${e2.constructor.name} intentionally unimplmented.  It is not concrete enough to interoperate.  Convert to Uint8Array first.`);
  }
  ce(ArrayBuffer, w2), ce(DataView, w2), typeof SharedArrayBuffer < "u" && ce(SharedArrayBuffer, w2);
  function m(e2) {
    return [NaN, e2.valueOf()];
  }
  ce(Boolean, m), ce(Number, m), ce(String, m), ce(BigInt, m);

  // node_modules/cbor2/lib/version.js
  var o4 = "2.0.1";

  // node_modules/cbor2/lib/decoder.js
  function c3(i3) {
    const e2 = { ...w.defaultDecodeOptions };
    if (i3.dcbor ? Object.assign(e2, w.dcborDecodeOptions) : i3.cde && Object.assign(e2, w.cdeDecodeOptions), Object.assign(e2, i3), Object.hasOwn(e2, "rejectLongNumbers")) throw new TypeError("rejectLongNumbers has changed to requirePreferred");
    return e2.boxed && (e2.saveOriginal = true), e2;
  }
  var d3 = class {
    constructor() {
      __publicField(this, "parent");
      __publicField(this, "ret");
    }
    step(e2, n2, t3) {
      if (this.ret = w.create(e2, this.parent, n2, t3), e2[2] === N.BREAK) if (this.parent?.isStreaming) this.parent.left = 0;
      else throw new Error("Unexpected BREAK");
      else this.parent && this.parent.push(this.ret, t3, e2[3]);
      for (this.ret instanceof w && (this.parent = this.ret); this.parent?.done; ) {
        this.ret = this.parent.convert(t3);
        const r2 = this.parent.parent;
        r2?.replaceLast(this.ret, this.parent, t3), this.parent = r2;
      }
    }
  };
  function l5(i3, e2 = {}) {
    const n2 = c3(e2), t3 = new y3(i3, n2), r2 = new d3();
    for (const o5 of t3) r2.step(o5, n2, t3);
    return r2.ret;
  }
  var _t5, _e6, _O_instances, n_fn3;
  var O4 = class {
    constructor(e2, n2 = {}) {
      __privateAdd(this, _O_instances);
      __privateAdd(this, _t5);
      __privateAdd(this, _e6);
      const t3 = new y3(e2, c3(n2));
      __privateSet(this, _t5, t3.seq());
    }
    peek() {
      return __privateGet(this, _e6) || __privateSet(this, _e6, __privateMethod(this, _O_instances, n_fn3).call(this)), __privateGet(this, _e6);
    }
    read() {
      const e2 = __privateGet(this, _e6) ?? __privateMethod(this, _O_instances, n_fn3).call(this);
      return __privateSet(this, _e6, void 0), e2;
    }
    *[Symbol.iterator]() {
      for (; ; ) {
        const e2 = this.read();
        if (!e2) return;
        yield e2;
      }
    }
  };
  _t5 = new WeakMap();
  _e6 = new WeakMap();
  _O_instances = new WeakSet();
  n_fn3 = function() {
    const { value: e2, done: n2 } = __privateGet(this, _t5).next();
    if (!n2) return e2;
  };
  function* b3(i3, e2 = {}) {
    const n2 = c3(e2), t3 = new y3(i3, n2), r2 = new d3();
    for (const o5 of t3.seq()) r2.step(o5, n2, t3), r2.parent || (yield r2.ret);
  }

  // node_modules/cbor2/lib/index.js
  var { cdeDecodeOptions: r, dcborDecodeOptions: n, defaultDecodeOptions: d4 } = w;

  // src/cose-sign1.js
  var cose_sign1_exports = {};
  __export(cose_sign1_exports, {
    Alg: () => Alg,
    Algorithm: () => Algorithm,
    COSE_Sign1_Tag: () => COSE_Sign1_Tag,
    CoseCurve: () => CoseCurve,
    CoseKeyParam: () => CoseKeyParam,
    CoseKeyType: () => CoseKeyType,
    HeaderParam: () => HeaderParam,
    computeCoseKeyThumbprint: () => computeCoseKeyThumbprint,
    coseKeyFromHex: () => coseKeyFromHex,
    coseKeyThumbprint: () => coseKeyThumbprint,
    coseKeyThumbprintUri: () => coseKeyThumbprintUri,
    coseKeyToHex: () => coseKeyToHex,
    coseKeyToInternal: () => coseKeyToInternal,
    deserializeCoseKey: () => deserializeCoseKey,
    generateKeyPair: () => generateKeyPair2,
    getAlgorithmFromCoseKey: () => getAlgorithmFromCoseKey,
    getCrypto: () => getCrypto,
    getHeaders: () => getHeaders,
    internalToCoseKey: () => internalToCoseKey,
    isCoseKey: () => isCoseKey,
    serializeCoseKey: () => serializeCoseKey,
    sign: () => sign3,
    verify: () => verify3
  });

  // src/crypto-browser.js
  var webcrypto = typeof globalThis.crypto !== "undefined" ? globalThis.crypto : null;
  if (!webcrypto) {
    throw new Error("Web Crypto API not available. Are you running in a secure context (HTTPS)?");
  }
  var SHA256 = (() => {
    const K2 = new Uint32Array([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    const H_INIT = new Uint32Array([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    function rotr(x4, n2) {
      return (x4 >>> n2 | x4 << 32 - n2) >>> 0;
    }
    function ch(x4, y6, z2) {
      return (x4 & y6 ^ ~x4 & z2) >>> 0;
    }
    function maj(x4, y6, z2) {
      return (x4 & y6 ^ x4 & z2 ^ y6 & z2) >>> 0;
    }
    function sigma0(x4) {
      return (rotr(x4, 2) ^ rotr(x4, 13) ^ rotr(x4, 22)) >>> 0;
    }
    function sigma1(x4) {
      return (rotr(x4, 6) ^ rotr(x4, 11) ^ rotr(x4, 25)) >>> 0;
    }
    function gamma0(x4) {
      return (rotr(x4, 7) ^ rotr(x4, 18) ^ x4 >>> 3) >>> 0;
    }
    function gamma1(x4) {
      return (rotr(x4, 17) ^ rotr(x4, 19) ^ x4 >>> 10) >>> 0;
    }
    function hash(message) {
      const msgLen = message.length;
      const bitLen = msgLen * 8;
      const padLen = msgLen + 9 + 63 & ~63;
      const padded = new Uint8Array(padLen);
      padded.set(message);
      padded[msgLen] = 128;
      const view = new DataView(padded.buffer);
      view.setUint32(padLen - 4, bitLen, false);
      const H3 = new Uint32Array(H_INIT);
      const W = new Uint32Array(64);
      for (let i3 = 0; i3 < padLen; i3 += 64) {
        for (let t3 = 0; t3 < 16; t3++) {
          W[t3] = view.getUint32(i3 + t3 * 4, false);
        }
        for (let t3 = 16; t3 < 64; t3++) {
          W[t3] = gamma1(W[t3 - 2]) + W[t3 - 7] + gamma0(W[t3 - 15]) + W[t3 - 16] >>> 0;
        }
        let a3 = H3[0], b4 = H3[1], c4 = H3[2], d5 = H3[3];
        let e2 = H3[4], f6 = H3[5], g4 = H3[6], h4 = H3[7];
        for (let t3 = 0; t3 < 64; t3++) {
          const T1 = h4 + sigma1(e2) + ch(e2, f6, g4) + K2[t3] + W[t3] >>> 0;
          const T22 = sigma0(a3) + maj(a3, b4, c4) >>> 0;
          h4 = g4;
          g4 = f6;
          f6 = e2;
          e2 = d5 + T1 >>> 0;
          d5 = c4;
          c4 = b4;
          b4 = a3;
          a3 = T1 + T22 >>> 0;
        }
        H3[0] = H3[0] + a3 >>> 0;
        H3[1] = H3[1] + b4 >>> 0;
        H3[2] = H3[2] + c4 >>> 0;
        H3[3] = H3[3] + d5 >>> 0;
        H3[4] = H3[4] + e2 >>> 0;
        H3[5] = H3[5] + f6 >>> 0;
        H3[6] = H3[6] + g4 >>> 0;
        H3[7] = H3[7] + h4 >>> 0;
      }
      const result = new Uint8Array(32);
      const resultView = new DataView(result.buffer);
      for (let i3 = 0; i3 < 8; i3++) {
        resultView.setUint32(i3 * 4, H3[i3], false);
      }
      return result;
    }
    return { hash };
  })();
  async function hashAsync(algorithm, data) {
    const algoMap = {
      "sha256": "SHA-256",
      "sha384": "SHA-384",
      "sha512": "SHA-512"
    };
    const algoName = algoMap[algorithm.toLowerCase()];
    if (!algoName) {
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }
    const hashBuffer = await webcrypto.subtle.digest(algoName, data);
    return new Uint8Array(hashBuffer);
  }
  function createHash(algorithm) {
    const normalizedAlg = algorithm.toLowerCase().replace("-", "");
    if (normalizedAlg !== "sha256") {
      throw new Error(`Synchronous hashing only supports sha256 in browser, got: ${algorithm}`);
    }
    let data = new Uint8Array(0);
    return {
      update(input) {
        const inputBytes = input instanceof Uint8Array ? input : ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
        const newData = new Uint8Array(data.length + inputBytes.length);
        newData.set(data);
        newData.set(inputBytes, data.length);
        data = newData;
        return this;
      },
      digest() {
        return SHA256.hash(data);
      }
    };
  }
  function randomBytes(size) {
    const bytes = new Uint8Array(size);
    webcrypto.getRandomValues(bytes);
    return bytes;
  }
  async function generateKeyPairAsync(algorithmOrCurve) {
    const curveMap = {
      "ES256": "P-256",
      "ES384": "P-384",
      "ES512": "P-521",
      "P-256": "P-256",
      "P-384": "P-384",
      "P-521": "P-521"
    };
    const namedCurve = curveMap[algorithmOrCurve] || algorithmOrCurve;
    const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve
      },
      true,
      ["sign", "verify"]
    );
    const privateJwk = await webcrypto.subtle.exportKey("jwk", keyPair.privateKey);
    const publicJwk = await webcrypto.subtle.exportKey("jwk", keyPair.publicKey);
    const base64urlDecode = (str) => {
      const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
      const pad = base64.length % 4;
      const padded = pad ? base64 + "=".repeat(4 - pad) : base64;
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i3 = 0; i3 < binary.length; i3++) {
        bytes[i3] = binary.charCodeAt(i3);
      }
      return bytes;
    };
    return {
      privateKey: {
        d: base64urlDecode(privateJwk.d),
        x: base64urlDecode(privateJwk.x),
        y: base64urlDecode(privateJwk.y)
      },
      publicKey: {
        x: base64urlDecode(publicJwk.x),
        y: base64urlDecode(publicJwk.y)
      }
    };
  }
  function createPrivateKey(options) {
    return {
      _jwk: options.key,
      _type: "private"
    };
  }
  function createPublicKey(options) {
    const { kty, crv, x: x4, y: y6 } = options.key;
    return {
      _jwk: { kty, crv, x: x4, y: y6 },
      _type: "public"
    };
  }
  function toBytes(data) {
    if (!data) {
      return new Uint8Array(0);
    }
    if (data instanceof Uint8Array) {
      const copy = new Uint8Array(data.length);
      copy.set(data);
      return copy;
    }
    if (ArrayBuffer.isView(data)) {
      const view = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      const copy = new Uint8Array(view.length);
      copy.set(view);
      return copy;
    }
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (Array.isArray(data)) {
      return new Uint8Array(data);
    }
    if (data && typeof data === "object" && "buffer" in data && data.buffer instanceof ArrayBuffer) {
      const view = new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength || data.length);
      const copy = new Uint8Array(view.length);
      copy.set(view);
      return copy;
    }
    return new Uint8Array(data);
  }
  async function sign(algorithm, data, options) {
    if (!options || !options.key) {
      throw new Error("sign: options.key is required");
    }
    if (!options.key._jwk) {
      throw new Error("sign: options.key._jwk is missing. Did you use createPrivateKey?");
    }
    const jwk = options.key._jwk;
    const namedCurve = jwk.crv;
    if (!namedCurve) {
      throw new Error(`sign: JWK missing crv property. Got: ${JSON.stringify(Object.keys(jwk))}`);
    }
    const hashMap = {
      "P-256": "SHA-256",
      "P-384": "SHA-384",
      "P-521": "SHA-512"
    };
    const hashName = hashMap[namedCurve];
    if (!hashName) {
      throw new Error(`sign: Unsupported curve: ${namedCurve}`);
    }
    const dataBytes = toBytes(data);
    const cryptoKey = await webcrypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve },
      false,
      ["sign"]
    );
    const signature = await webcrypto.subtle.sign(
      { name: "ECDSA", hash: hashName },
      cryptoKey,
      dataBytes
    );
    return new Uint8Array(signature);
  }
  async function verify(algorithm, data, options, signature) {
    if (!options || !options.key) {
      throw new Error("verify: options.key is required");
    }
    if (!options.key._jwk) {
      throw new Error("verify: options.key._jwk is missing. Did you use createPublicKey?");
    }
    const jwk = options.key._jwk;
    const namedCurve = jwk.crv;
    if (!namedCurve) {
      throw new Error(`verify: JWK missing crv property. Got: ${JSON.stringify(Object.keys(jwk))}`);
    }
    const hashMap = {
      "P-256": "SHA-256",
      "P-384": "SHA-384",
      "P-521": "SHA-512"
    };
    const hashName = hashMap[namedCurve];
    if (!hashName) {
      throw new Error(`verify: Unsupported curve: ${namedCurve}`);
    }
    const dataBytes = toBytes(data);
    const sigBytes = toBytes(signature);
    const cryptoKey = await webcrypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve },
      false,
      ["verify"]
    );
    const result = await webcrypto.subtle.verify(
      { name: "ECDSA", hash: hashName },
      cryptoKey,
      sigBytes,
      dataBytes
    );
    return result;
  }
  function generateKeyPairSync(type, options) {
    throw new Error("generateKeyPairSync not available in browser. Use generateKeyPair() async version.");
  }
  var crypto_browser_default = {
    randomBytes,
    createHash,
    createPrivateKey,
    createPublicKey,
    sign,
    verify,
    generateKeyPair: generateKeyPairAsync,
    generateKeyPairSync,
    hashAsync,
    subtle: webcrypto?.subtle
  };

  // src/cose/sign1.js
  var COSE_Sign1_Tag = 18;
  var HeaderParam = {
    Algorithm: 1,
    Critical: 2,
    ContentType: 3,
    KeyId: 4,
    IV: 5,
    PartialIV: 6,
    CounterSignature: 7,
    CounterSignature0: 9,
    X5Bag: 32,
    X5Chain: 33,
    X5T: 34,
    X5U: 35
  };
  var Alg = {
    ES256: -7,
    // ECDSA w/ SHA-256
    ES384: -35,
    // ECDSA w/ SHA-384
    ES512: -36
    // ECDSA w/ SHA-512
  };
  var cborDecodeOptions = {
    preferMap: true
  };
  var AlgInfo = {
    [Alg.ES256]: { name: "ES256", curve: "P-256", hash: "sha256", sigSize: 64 },
    [Alg.ES384]: { name: "ES384", curve: "P-384", hash: "sha384", sigSize: 96 },
    [Alg.ES512]: { name: "ES512", curve: "P-521", hash: "sha512", sigSize: 132 }
  };
  function copyBytes(data) {
    if (!data || data.length === 0) {
      return data;
    }
    if (data instanceof Uint8Array) {
      const copy = new Uint8Array(data.length);
      copy.set(data);
      return copy;
    }
    if (ArrayBuffer.isView(data)) {
      const view = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      const copy = new Uint8Array(view.length);
      copy.set(view);
      return copy;
    }
    return data;
  }
  function createSigStructure(protectedHeader, payload, externalAad = new Uint8Array(0)) {
    const structure = [
      "Signature1",
      protectedHeader,
      externalAad,
      payload
    ];
    return Q(structure);
  }
  async function sign2(options) {
    const {
      protectedHeader,
      unprotectedHeader = /* @__PURE__ */ new Map(),
      payload,
      key,
      externalAad = new Uint8Array(0)
    } = options;
    if (!(protectedHeader instanceof Map)) {
      throw new TypeError("protectedHeader must be a Map");
    }
    if (!(unprotectedHeader instanceof Map)) {
      throw new TypeError("unprotectedHeader must be a Map");
    }
    if (!payload) {
      throw new Error("payload is required");
    }
    if (!key || !key.d || !key.x || !key.y) {
      throw new Error("key must include d, x, and y components");
    }
    const alg = protectedHeader.get(HeaderParam.Algorithm);
    if (alg === void 0) {
      throw new Error("Algorithm (1) must be in protected header");
    }
    const algInfo = AlgInfo[alg];
    if (!algInfo) {
      throw new Error(`Unsupported algorithm: ${alg}`);
    }
    const protectedBytes = protectedHeader.size > 0 ? Q(protectedHeader) : new Uint8Array(0);
    let payloadBytes;
    if (Buffer2.isBuffer(payload)) {
      payloadBytes = new Uint8Array(payload.buffer, payload.byteOffset, payload.length);
    } else if (payload instanceof Uint8Array) {
      payloadBytes = payload;
    } else {
      payloadBytes = new Uint8Array(Buffer2.from(payload));
    }
    const sigStructure = createSigStructure(protectedBytes, payloadBytes, externalAad);
    const signature = await signECDSA(sigStructure, key, algInfo);
    const coseSign1 = [
      protectedBytes,
      unprotectedHeader,
      payloadBytes,
      signature
    ];
    return Q(new i(COSE_Sign1_Tag, coseSign1));
  }
  async function verify2(coseSign1, key, externalAad = new Uint8Array(0)) {
    if (!coseSign1) {
      throw new Error("COSE_Sign1 message is required");
    }
    if (!key || !key.x || !key.y) {
      throw new Error("key must include x and y components");
    }
    const decoded = l5(coseSign1, cborDecodeOptions);
    const structure = decoded instanceof i ? decoded.contents : decoded;
    if (!Array.isArray(structure) || structure.length !== 4) {
      throw new Error("Invalid COSE_Sign1 structure");
    }
    const [protectedBytesRaw, , payloadRaw, signatureRaw] = structure;
    const protectedBytes = copyBytes(protectedBytesRaw);
    const payload = copyBytes(payloadRaw);
    const signature = copyBytes(signatureRaw);
    let protectedHeader = /* @__PURE__ */ new Map();
    if (protectedBytes && protectedBytes.length > 0) {
      const decodedProtected = l5(protectedBytes, cborDecodeOptions);
      protectedHeader = decodedProtected instanceof Map ? decodedProtected : new Map(Object.entries(decodedProtected));
    }
    const alg = protectedHeader.get(HeaderParam.Algorithm);
    if (alg === void 0) {
      throw new Error("Algorithm not found in protected header");
    }
    const algInfo = AlgInfo[alg];
    if (!algInfo) {
      throw new Error(`Unsupported algorithm: ${alg}`);
    }
    const sigStructure = createSigStructure(protectedBytes, payload, externalAad);
    const isValid = await verifyECDSA(sigStructure, signature, key, algInfo);
    if (!isValid) {
      throw new Error("Signature verification failed");
    }
    return payload;
  }
  function decode(coseSign1) {
    if (!coseSign1) {
      throw new Error("COSE_Sign1 message is required");
    }
    const decoded = l5(coseSign1, cborDecodeOptions);
    const structure = decoded instanceof i ? decoded.contents : decoded;
    if (!Array.isArray(structure) || structure.length !== 4) {
      throw new Error("Invalid COSE_Sign1 structure");
    }
    const [protectedBytesRaw, unprotectedHeader, payloadRaw, signatureRaw] = structure;
    const protectedBytes = copyBytes(protectedBytesRaw);
    const payload = copyBytes(payloadRaw);
    const signature = copyBytes(signatureRaw);
    let protectedHeader = /* @__PURE__ */ new Map();
    if (protectedBytes && protectedBytes.length > 0) {
      const decodedHeader = l5(protectedBytes, cborDecodeOptions);
      protectedHeader = decodedHeader instanceof Map ? decodedHeader : new Map(Object.entries(decodedHeader).map(([k4, v2]) => [Number(k4), v2]));
    }
    let unprotected = unprotectedHeader;
    if (!(unprotected instanceof Map)) {
      unprotected = new Map(Object.entries(unprotected || {}).map(([k4, v2]) => [Number(k4), v2]));
    }
    return {
      protectedHeader,
      unprotectedHeader: unprotected,
      payload,
      signature
    };
  }
  async function signECDSA(data, key, algInfo) {
    const jwk = {
      kty: "EC",
      crv: algInfo.curve,
      d: Buffer2.from(key.d).toString("base64url"),
      x: Buffer2.from(key.x).toString("base64url"),
      y: Buffer2.from(key.y).toString("base64url")
    };
    const privateKey = crypto_browser_default.createPrivateKey({ key: jwk, format: "jwk" });
    const signature = await crypto_browser_default.sign(null, data, { key: privateKey, dsaEncoding: "ieee-p1363" });
    return new Uint8Array(signature);
  }
  async function verifyECDSA(data, signature, key, algInfo) {
    let sigBytes;
    if (signature instanceof Uint8Array) {
      sigBytes = new Uint8Array(signature.length);
      sigBytes.set(signature);
    } else if (ArrayBuffer.isView(signature)) {
      sigBytes = new Uint8Array(signature.buffer, signature.byteOffset, signature.byteLength);
      const copy = new Uint8Array(sigBytes.length);
      copy.set(sigBytes);
      sigBytes = copy;
    } else {
      sigBytes = new Uint8Array(Buffer2.from(signature));
    }
    const jwk = {
      kty: "EC",
      crv: algInfo.curve,
      x: Buffer2.from(key.x).toString("base64url"),
      y: Buffer2.from(key.y).toString("base64url")
    };
    const publicKey = crypto_browser_default.createPublicKey({ key: jwk, format: "jwk" });
    const sigBuffer = Buffer2.from(sigBytes);
    return await crypto_browser_default.verify(null, data, { key: publicKey, dsaEncoding: "ieee-p1363" }, sigBuffer);
  }
  function generateKeyPair(alg = Alg.ES256) {
    const algInfo = AlgInfo[alg];
    if (!algInfo) {
      throw new Error(`Unsupported algorithm: ${alg}`);
    }
    const { privateKey, publicKey } = crypto_browser_default.generateKeyPairSync("ec", {
      namedCurve: algInfo.curve
    });
    const privateJwk = privateKey.export({ format: "jwk" });
    const publicJwk = publicKey.export({ format: "jwk" });
    return {
      privateKey: {
        d: new Uint8Array(Buffer2.from(privateJwk.d, "base64url")),
        x: new Uint8Array(Buffer2.from(privateJwk.x, "base64url")),
        y: new Uint8Array(Buffer2.from(privateJwk.y, "base64url"))
      },
      publicKey: {
        x: new Uint8Array(Buffer2.from(publicJwk.x, "base64url")),
        y: new Uint8Array(Buffer2.from(publicJwk.y, "base64url"))
      }
    };
  }
  function getCrypto() {
    return crypto_browser_default;
  }

  // src/cose-sign1.js
  var Algorithm = {
    ES256: "ES256",
    ES384: "ES384",
    ES512: "ES512"
  };
  var CoseKeyParam = {
    Kty: 1,
    // Key Type
    Kid: 2,
    // Key ID
    Alg: 3,
    // Key Algorithm
    KeyOps: 4,
    // Key Operations
    BaseIV: 5,
    // Base IV
    // EC2 specific parameters
    Crv: -1,
    // Curve (EC2)
    X: -2,
    // x coordinate
    Y: -3,
    // y coordinate
    D: -4
    // Private key d
  };
  var CoseKeyType = {
    OKP: 1,
    // Octet Key Pair (EdDSA)
    EC2: 2
    // Elliptic Curve with x, y coordinates
  };
  var CoseCurve = {
    P256: 1,
    // NIST P-256 (secp256r1)
    P384: 2,
    // NIST P-384 (secp384r1)
    P521: 3
    // NIST P-521 (secp521r1)
  };
  var AlgToCurve = {
    "ES256": CoseCurve.P256,
    "ES384": CoseCurve.P384,
    "ES512": CoseCurve.P521
  };
  var CurveToAlg = {
    [CoseCurve.P256]: "ES256",
    [CoseCurve.P384]: "ES384",
    [CoseCurve.P521]: "ES512"
  };
  function isCoseKey(key) {
    if (key instanceof Map) {
      return key.has(CoseKeyParam.Kty) || key.has(CoseKeyParam.X);
    }
    if (typeof key === "object" && key !== null) {
      const keys = Object.keys(key);
      return keys.some((k4) => k4 === "1" || k4 === "-2" || k4 === "-3");
    }
    return false;
  }
  function coseKeyToInternal(coseKey) {
    let x4, y6, d5;
    if (coseKey instanceof Map) {
      x4 = coseKey.get(CoseKeyParam.X);
      y6 = coseKey.get(CoseKeyParam.Y);
      d5 = coseKey.get(CoseKeyParam.D);
    } else if (typeof coseKey === "object") {
      x4 = coseKey[CoseKeyParam.X] || coseKey["-2"];
      y6 = coseKey[CoseKeyParam.Y] || coseKey["-3"];
      d5 = coseKey[CoseKeyParam.D] || coseKey["-4"];
    }
    const result = {};
    if (x4) result.x = toUint8Array(x4);
    if (y6) result.y = toUint8Array(y6);
    if (d5) result.d = toUint8Array(d5);
    return result;
  }
  function internalToCoseKey(key, algorithm = "ES256") {
    const coseKey = /* @__PURE__ */ new Map();
    coseKey.set(CoseKeyParam.Kty, CoseKeyType.EC2);
    coseKey.set(CoseKeyParam.Crv, AlgToCurve[algorithm] || CoseCurve.P256);
    if (key.x) coseKey.set(CoseKeyParam.X, toUint8Array(key.x));
    if (key.y) coseKey.set(CoseKeyParam.Y, toUint8Array(key.y));
    if (key.d) coseKey.set(CoseKeyParam.D, toUint8Array(key.d));
    return coseKey;
  }
  function getAlgorithmFromCoseKey(coseKey) {
    let crv;
    if (coseKey instanceof Map) {
      crv = coseKey.get(CoseKeyParam.Crv);
    } else if (typeof coseKey === "object") {
      crv = coseKey[CoseKeyParam.Crv] || coseKey["-1"];
    }
    return CurveToAlg[crv] || "ES256";
  }
  function serializeCoseKey(coseKey) {
    if (!(coseKey instanceof Map)) {
      throw new Error("COSE Key must be a Map");
    }
    return new Uint8Array(Q(coseKey));
  }
  function deserializeCoseKey(bytes) {
    if (!bytes || bytes.length === 0) {
      throw new Error("COSE Key bytes are required");
    }
    const decoded = l5(bytes, { preferMap: true });
    if (!(decoded instanceof Map)) {
      throw new Error("Invalid COSE Key: expected a CBOR map");
    }
    if (!decoded.has(CoseKeyParam.Kty)) {
      throw new Error("Invalid COSE Key: missing kty (key type)");
    }
    return decoded;
  }
  function coseKeyToHex(coseKey) {
    const bytes = serializeCoseKey(coseKey);
    return Array.from(bytes).map((b4) => b4.toString(16).padStart(2, "0")).join("");
  }
  function coseKeyFromHex(hex) {
    if (!hex || typeof hex !== "string") {
      throw new Error("Hex string is required");
    }
    const clean = hex.replace(/\s/g, "");
    const bytes = new Uint8Array(clean.length / 2);
    for (let i3 = 0; i3 < bytes.length; i3++) {
      bytes[i3] = parseInt(clean.substr(i3 * 2, 2), 16);
    }
    return deserializeCoseKey(bytes);
  }
  function computeCoseKeyThumbprint(coseKey, hashAlgorithm = "SHA-256") {
    let kty, crv, x4, y6;
    if (coseKey instanceof Map) {
      kty = coseKey.get(CoseKeyParam.Kty);
      crv = coseKey.get(CoseKeyParam.Crv);
      x4 = coseKey.get(CoseKeyParam.X);
      y6 = coseKey.get(CoseKeyParam.Y);
    } else if (typeof coseKey === "object") {
      kty = coseKey[CoseKeyParam.Kty] || coseKey["1"];
      crv = coseKey[CoseKeyParam.Crv] || coseKey["-1"];
      x4 = coseKey[CoseKeyParam.X] || coseKey["-2"];
      y6 = coseKey[CoseKeyParam.Y] || coseKey["-3"];
    } else {
      throw new Error("COSE Key must be a Map or Object");
    }
    if (kty !== CoseKeyType.EC2) {
      throw new Error(`Unsupported key type for thumbprint: ${kty}. Only EC2 (2) is supported.`);
    }
    if (crv === void 0 || !x4 || !y6) {
      throw new Error("COSE Key must have crv, x, and y parameters for thumbprint");
    }
    const thumbprintParams = /* @__PURE__ */ new Map();
    thumbprintParams.set(CoseKeyParam.Kty, kty);
    thumbprintParams.set(CoseKeyParam.Crv, crv);
    thumbprintParams.set(CoseKeyParam.X, toUint8Array(x4));
    thumbprintParams.set(CoseKeyParam.Y, toUint8Array(y6));
    const encoded = Q(thumbprintParams);
    const crypto = getCrypto();
    const hash = crypto.createHash(hashAlgorithm.toLowerCase().replace("-", ""));
    hash.update(new Uint8Array(encoded));
    const digest = hash.digest();
    return new Uint8Array(digest);
  }
  function coseKeyThumbprint(coseKey, hashAlgorithm = "SHA-256") {
    const bytes = computeCoseKeyThumbprint(coseKey, hashAlgorithm);
    return Array.from(bytes).map((b4) => b4.toString(16).padStart(2, "0")).join("");
  }
  function coseKeyThumbprintUri(coseKey, hashAlgorithm = "SHA-256") {
    const bytes = computeCoseKeyThumbprint(coseKey, hashAlgorithm);
    let binary = "";
    for (let i3 = 0; i3 < bytes.length; i3++) {
      binary += String.fromCharCode(bytes[i3]);
    }
    const base64 = btoa(binary);
    const base64url = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const hashName = hashAlgorithm.toLowerCase();
    return `urn:ietf:params:oauth:ckt:${hashName}:${base64url}`;
  }
  function normalizeKey(key) {
    if (isCoseKey(key)) {
      return {
        key: coseKeyToInternal(key),
        algorithm: getAlgorithmFromCoseKey(key)
      };
    }
    return {
      key: {
        d: key.d ? toUint8Array(key.d) : void 0,
        x: key.x ? toUint8Array(key.x) : void 0,
        y: key.y ? toUint8Array(key.y) : void 0
      },
      algorithm: "ES256"
      // Default for legacy format
    };
  }
  var AlgNameToId = {
    "ES256": Alg.ES256,
    "ES384": Alg.ES384,
    "ES512": Alg.ES512
  };
  async function sign3(payload, signerKey, options = {}) {
    const {
      algorithm: explicitAlgorithm,
      kid,
      protectedHeaders = {},
      unprotectedHeaders = {},
      customProtectedHeaders,
      customUnprotectedHeaders
    } = options;
    if (!payload) {
      throw new Error("Payload is required");
    }
    const { key: internalKey, algorithm: detectedAlgorithm } = normalizeKey(signerKey);
    const algorithm = explicitAlgorithm || detectedAlgorithm;
    if (!internalKey || !internalKey.d || !internalKey.x || !internalKey.y) {
      throw new Error("Signer key must include d, x, and y components (COSE Key params -4, -2, -3)");
    }
    const algId = AlgNameToId[algorithm];
    if (algId === void 0) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    const protectedMap = /* @__PURE__ */ new Map();
    protectedMap.set(HeaderParam.Algorithm, algId);
    for (const [key2, value] of Object.entries(protectedHeaders)) {
      const label = HeaderLabels[key2];
      if (label !== void 0) {
        protectedMap.set(label, value);
      }
    }
    if (customProtectedHeaders) {
      const entries = customProtectedHeaders instanceof Map ? customProtectedHeaders.entries() : Object.entries(customProtectedHeaders);
      for (const [key2, value] of entries) {
        protectedMap.set(Number(key2), convertBufferValues(value));
      }
    }
    const unprotectedMap = /* @__PURE__ */ new Map();
    if (kid) {
      const kidBuffer = typeof kid === "string" ? Buffer2.from(kid) : kid;
      const kidValue = toUint8Array(kidBuffer);
      unprotectedMap.set(HeaderParam.KeyId, kidValue);
    }
    for (const [key2, value] of Object.entries(unprotectedHeaders)) {
      const label = HeaderLabels[key2];
      if (label !== void 0) {
        unprotectedMap.set(label, value);
      }
    }
    if (customUnprotectedHeaders) {
      const entries = customUnprotectedHeaders instanceof Map ? customUnprotectedHeaders.entries() : Object.entries(customUnprotectedHeaders);
      for (const [key2, value] of entries) {
        unprotectedMap.set(Number(key2), convertBufferValues(value));
      }
    }
    let payloadBytes;
    if (payload instanceof Uint8Array) {
      payloadBytes = payload;
    } else if (Buffer2.isBuffer(payload)) {
      payloadBytes = new Uint8Array(payload);
    } else {
      payloadBytes = new Uint8Array(Buffer2.from(payload));
    }
    const key = internalKey;
    const signed = await sign2({
      protectedHeader: protectedMap,
      unprotectedHeader: unprotectedMap,
      payload: payloadBytes,
      key
    });
    return Buffer2.from(signed);
  }
  async function verify3(coseSign1, verifierKey) {
    if (!coseSign1) {
      throw new Error("COSE Sign1 message is required");
    }
    const { key: internalKey } = normalizeKey(verifierKey);
    if (!internalKey || !internalKey.x || !internalKey.y) {
      throw new Error("Verifier key must include x and y components (COSE Key params -2, -3)");
    }
    const messageBytes = toUint8Array(coseSign1);
    const payload = await verify2(messageBytes, internalKey);
    return Buffer2.from(payload);
  }
  function getHeaders(coseSign1) {
    if (!coseSign1) {
      throw new Error("COSE Sign1 message is required");
    }
    const messageBytes = toUint8Array(coseSign1);
    const decoded = decode(messageBytes);
    return {
      protectedHeaders: decoded.protectedHeader,
      unprotectedHeaders: decoded.unprotectedHeader
    };
  }
  function generateKeyPair2(algorithm = Algorithm.ES256) {
    const algId = AlgNameToId[algorithm];
    if (algId === void 0) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    const { privateKey, publicKey } = generateKeyPair(algId);
    const curve = AlgToCurve[algorithm];
    const privateKeyMap = /* @__PURE__ */ new Map();
    privateKeyMap.set(CoseKeyParam.Kty, CoseKeyType.EC2);
    privateKeyMap.set(CoseKeyParam.Crv, curve);
    privateKeyMap.set(CoseKeyParam.X, new Uint8Array(privateKey.x));
    privateKeyMap.set(CoseKeyParam.Y, new Uint8Array(privateKey.y));
    privateKeyMap.set(CoseKeyParam.D, new Uint8Array(privateKey.d));
    const publicKeyMap = /* @__PURE__ */ new Map();
    publicKeyMap.set(CoseKeyParam.Kty, CoseKeyType.EC2);
    publicKeyMap.set(CoseKeyParam.Crv, curve);
    publicKeyMap.set(CoseKeyParam.X, new Uint8Array(publicKey.x));
    publicKeyMap.set(CoseKeyParam.Y, new Uint8Array(publicKey.y));
    return {
      privateKey: privateKeyMap,
      publicKey: publicKeyMap
    };
  }
  var HeaderLabels = {
    alg: HeaderParam.Algorithm,
    crit: HeaderParam.Critical,
    content_type: HeaderParam.ContentType,
    ctyp: HeaderParam.ContentType,
    kid: HeaderParam.KeyId,
    IV: HeaderParam.IV,
    Partial_IV: HeaderParam.PartialIV,
    counter_signature: HeaderParam.CounterSignature,
    x5chain: HeaderParam.X5Chain
  };
  function toUint8Array(value) {
    if (Buffer2.isBuffer(value)) {
      const copy = new Uint8Array(value.length);
      copy.set(value);
      return copy;
    }
    if (value instanceof Uint8Array) {
      const copy = new Uint8Array(value.length);
      copy.set(value);
      return copy;
    }
    return new Uint8Array(Buffer2.from(value));
  }
  function convertBufferValues(value) {
    if (Buffer2.isBuffer(value)) {
      const copy = new Uint8Array(value.length);
      copy.set(value);
      return copy;
    }
    if (value instanceof Uint8Array) {
      const copy = new Uint8Array(value.length);
      copy.set(value);
      return copy;
    }
    if (Array.isArray(value)) {
      return value.map(convertBufferValues);
    }
    if (value instanceof Map) {
      const result = /* @__PURE__ */ new Map();
      for (const [k4, v2] of value) {
        result.set(k4, convertBufferValues(v2));
      }
      return result;
    }
    if (value !== null && typeof value === "object") {
      const result = {};
      for (const [k4, v2] of Object.entries(value)) {
        result[k4] = convertBufferValues(v2);
      }
      return result;
    }
    return value;
  }

  // src/sd-cwt.js
  var sd_cwt_exports = {};
  __export(sd_cwt_exports, {
    ClaimKey: () => ClaimKey,
    HeaderParam: () => HeaderParam2,
    MAX_DEPTH: () => MAX_DEPTH,
    MediaType: () => MediaType,
    SdAlg: () => SdAlg,
    SimpleValue: () => SimpleValue,
    Tag: () => Tag,
    assertClaimsClean: () => assertClaimsClean,
    cborDecodeOptions: () => cborDecodeOptions2,
    createArrayElementDisclosure: () => createArrayElementDisclosure,
    createSaltedDisclosure: () => createSaltedDisclosure,
    decodeDisclosure: () => decodeDisclosure,
    generateSalt: () => generateSalt,
    getRedactedElementContents: () => getRedactedElementContents,
    getTagContents: () => getTagContents,
    hashDisclosure: () => hashDisclosure,
    isRedactedClaimElement: () => isRedactedClaimElement,
    isRedactedKeysKey: () => isRedactedKeysKey,
    isToBeDecoy: () => isToBeDecoy,
    isToBeRedacted: () => isToBeRedacted,
    processArrayToBeRedacted: () => processArrayToBeRedacted,
    processToBeRedacted: () => processToBeRedacted,
    reconstructArray: () => reconstructArray,
    reconstructClaims: () => reconstructClaims,
    redactedClaimElement: () => redactedClaimElement,
    redactedKeysKey: () => redactedKeysKey,
    simple: () => simple,
    toBeDecoy: () => toBeDecoy,
    toBeRedacted: () => toBeRedacted,
    validateClaimsClean: () => validateClaimsClean
  });
  var MAX_DEPTH = 16;
  var Tag = {
    /** Tag 58: Wraps claims intended to be redacted (used in pre-issuance) */
    ToBeRedacted: 58,
    /** Tag 60: Wraps a redacted array element (contains hash) */
    RedactedClaimElement: 60,
    /** Tag 61: Wraps a decoy value to be inserted */
    ToBeDecoy: 61
  };
  var SimpleValue = {
    /** Simple value 59: Map key for array of redacted claim key hashes */
    RedactedKeys: 59
  };
  var HeaderParam2 = {
    /** alg: Algorithm */
    Alg: 1,
    /** kid: Key identifier */
    Kid: 4,
    /** kcwt: Key Binding CWT (contains the SD-CWT in SD-KBT) */
    Kcwt: 13,
    /** CWT_Claims: CWT Claims header parameter (RFC 9597) - claims in protected header */
    CwtClaims: 15,
    /** typ: Content type */
    Typ: 16,
    /** sd_claims: Array of selectively disclosed claims */
    SdClaims: 17,
    /** sd_alg: Hash algorithm used for redaction */
    SdAlg: 18,
    /** sd_aead_encrypted_claims */
    SdAeadEncryptedClaims: 19,
    /** sd_aead */
    SdAead: 20
  };
  var ClaimKey = {
    /** iss: Issuer */
    Iss: 1,
    /** sub: Subject */
    Sub: 2,
    /** aud: Audience */
    Aud: 3,
    /** exp: Expiration time */
    Exp: 4,
    /** nbf: Not before */
    Nbf: 5,
    /** iat: Issued at */
    Iat: 6,
    /** cti: CWT ID */
    Cti: 7,
    /** cnf: Confirmation (from RFC 8747) */
    Cnf: 8,
    /** cnonce: Client nonce */
    Cnonce: 39
  };
  var MediaType = {
    SdCwt: "application/sd-cwt",
    KbCwt: "application/kb+cwt"
  };
  var SdAlg = {
    SHA256: -16
  };
  var cborDecodeOptions2 = {
    preferMap: true
  };
  function toBeRedacted(value) {
    return new i(Tag.ToBeRedacted, value);
  }
  function toBeDecoy(count) {
    if (!Number.isInteger(count) || count < 1) {
      throw new Error("Decoy count must be a positive integer");
    }
    return new i(Tag.ToBeDecoy, count);
  }
  function redactedClaimElement(hash) {
    const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
    return new i(Tag.RedactedClaimElement, hashBytes);
  }
  function simple(value) {
    return new t2(value);
  }
  function redactedKeysKey() {
    return new t2(SimpleValue.RedactedKeys);
  }
  function isToBeRedacted(value) {
    return value instanceof i && value.tag === Tag.ToBeRedacted;
  }
  function isRedactedClaimElement(value) {
    if (value instanceof i && value.tag === Tag.RedactedClaimElement) {
      return true;
    }
    if (value instanceof Map && value.get("tag") === Tag.RedactedClaimElement) {
      return true;
    }
    return false;
  }
  function getRedactedElementContents(value) {
    if (value instanceof i) {
      return value.contents;
    }
    if (value instanceof Map) {
      return value.get("contents");
    }
    throw new Error("Invalid redacted claim element");
  }
  function isToBeDecoy(value) {
    return value instanceof i && value.tag === Tag.ToBeDecoy;
  }
  function isRedactedKeysKey(value) {
    return value instanceof t2 && value.value === SimpleValue.RedactedKeys;
  }
  function getTagContents(tag) {
    if (!(tag instanceof i)) {
      throw new Error("Value is not a CBOR tag");
    }
    return tag.contents;
  }
  function generateSalt() {
    return new Uint8Array(crypto_browser_default.randomBytes(16));
  }
  function createSaltedDisclosure(salt, value, claimName) {
    const disclosure = [salt, value, claimName];
    return Q(disclosure);
  }
  function createArrayElementDisclosure(salt, value) {
    const disclosure = [salt, value];
    return Q(disclosure);
  }
  function hashDisclosure(disclosure, algorithm = "sha256") {
    const hash = crypto_browser_default.createHash(algorithm);
    hash.update(disclosure);
    return new Uint8Array(hash.digest());
  }
  function checkDepth(depth, strict) {
    if (strict && depth > MAX_DEPTH) {
      throw new Error(`Depth ${depth} exceeds maximum allowed depth of ${MAX_DEPTH}`);
    }
  }
  function processValueRecursive(value, hashAlg, strict, depth) {
    checkDepth(depth, strict);
    if (value instanceof Map) {
      return processMapInternal(value, hashAlg, strict, depth);
    } else if (Array.isArray(value)) {
      return processArrayInternal(value, hashAlg, strict, depth);
    } else if (value instanceof i) {
      if (!isToBeRedacted(value) && !isToBeDecoy(value) && !isRedactedClaimElement(value)) {
        const { value: processedContents, disclosures } = processValueRecursive(
          value.contents,
          hashAlg,
          strict,
          depth + 1
        );
        return { value: new i(value.tag, processedContents), disclosures };
      }
    }
    return { value, disclosures: [] };
  }
  function processMapInternal(claims, hashAlg, strict, depth) {
    checkDepth(depth, strict);
    const resultClaims = /* @__PURE__ */ new Map();
    const disclosures = [];
    const redactedKeyHashes = [];
    for (const [key, value] of claims) {
      if (isToBeRedacted(key)) {
        const actualKey = getTagContents(key);
        const salt = generateSalt();
        const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
          value,
          hashAlg,
          strict,
          depth + 1
        );
        disclosures.push(...nestedDisclosures);
        const disclosure = createSaltedDisclosure(salt, processedValue, actualKey);
        const hash = hashDisclosure(disclosure, hashAlg);
        disclosures.push(disclosure);
        redactedKeyHashes.push(hash);
      } else if (isToBeDecoy(key)) {
        const count = getTagContents(key);
        for (let i3 = 0; i3 < count; i3++) {
          const salt = generateSalt();
          const decoyDisclosure = Q([salt]);
          const hash = hashDisclosure(decoyDisclosure, hashAlg);
          redactedKeyHashes.push(hash);
        }
      } else {
        const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
          value,
          hashAlg,
          strict,
          depth + 1
        );
        resultClaims.set(key, processedValue);
        disclosures.push(...nestedDisclosures);
      }
    }
    if (redactedKeyHashes.length > 0) {
      resultClaims.set(redactedKeysKey(), redactedKeyHashes);
    }
    return { value: resultClaims, claims: resultClaims, disclosures };
  }
  function processArrayInternal(array, hashAlg, strict, depth) {
    checkDepth(depth, strict);
    const resultArray = [];
    const disclosures = [];
    for (const element of array) {
      if (isToBeRedacted(element)) {
        const actualValue = getTagContents(element);
        const salt = generateSalt();
        const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
          actualValue,
          hashAlg,
          strict,
          depth + 1
        );
        disclosures.push(...nestedDisclosures);
        const disclosure = createArrayElementDisclosure(salt, processedValue);
        const hash = hashDisclosure(disclosure, hashAlg);
        disclosures.push(disclosure);
        resultArray.push(redactedClaimElement(hash));
      } else if (isToBeDecoy(element)) {
        const count = getTagContents(element);
        for (let i3 = 0; i3 < count; i3++) {
          const salt = generateSalt();
          const decoyDisclosure = Q([salt]);
          const hash = hashDisclosure(decoyDisclosure, hashAlg);
          resultArray.push(redactedClaimElement(hash));
        }
      } else {
        const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
          element,
          hashAlg,
          strict,
          depth + 1
        );
        resultArray.push(processedValue);
        disclosures.push(...nestedDisclosures);
      }
    }
    return { value: resultArray, array: resultArray, disclosures };
  }
  function processToBeRedacted(claims, hashAlgOrOptions = "sha256") {
    const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
    const result = processMapInternal(claims, hashAlg, strict, 1);
    return { claims: result.claims, disclosures: result.disclosures };
  }
  function normalizeOptions(hashAlgOrOptions) {
    if (typeof hashAlgOrOptions === "string") {
      return { hashAlg: hashAlgOrOptions, strict: false };
    }
    return {
      hashAlg: hashAlgOrOptions.hashAlg || "sha256",
      strict: hashAlgOrOptions.strict || false
    };
  }
  function processArrayToBeRedacted(array, hashAlgOrOptions = "sha256") {
    const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
    const result = processArrayInternal(array, hashAlg, strict, 1);
    return { array: result.array, disclosures: result.disclosures };
  }
  function decodeDisclosure(disclosure) {
    const decoded = l5(disclosure, cborDecodeOptions2);
    if (!Array.isArray(decoded)) {
      throw new Error("Invalid disclosure format: expected array");
    }
    if (decoded.length === 2) {
      return {
        salt: decoded[0],
        value: decoded[1]
      };
    } else if (decoded.length === 3) {
      return {
        salt: decoded[0],
        value: decoded[1],
        claimName: decoded[2]
      };
    } else if (decoded.length === 1) {
      return {
        salt: decoded[0],
        value: void 0,
        isDecoy: true
      };
    }
    throw new Error(`Invalid disclosure format: unexpected length ${decoded.length}`);
  }
  function buildDisclosureLookup(disclosures, hashAlg = "sha256") {
    const lookup = /* @__PURE__ */ new Map();
    for (const disclosure of disclosures) {
      const hash = hashDisclosure(disclosure, hashAlg);
      const decoded = decodeDisclosure(disclosure);
      const hexKey = Buffer2.from(hash).toString("hex");
      lookup.set(hexKey, { hash, decoded, disclosure });
    }
    return lookup;
  }
  function reconstructValueRecursive(value, lookup, strict, depth) {
    checkDepth(depth, strict);
    if (value instanceof Map) {
      const result = reconstructMapInternal(value, lookup, strict, depth);
      return { value: result.claims, redactedHashes: result.redactedKeys };
    } else if (Array.isArray(value)) {
      const result = reconstructArrayRecursive(value, lookup, strict, depth);
      return { value: result.array, redactedHashes: result.redactedElements };
    } else if (value instanceof i) {
      if (!isRedactedClaimElement(value)) {
        const { value: reconstructedContents, redactedHashes } = reconstructValueRecursive(
          value.contents,
          lookup,
          strict,
          depth + 1
        );
        return { value: new i(value.tag, reconstructedContents), redactedHashes };
      }
    }
    return { value, redactedHashes: [] };
  }
  function reconstructClaims(redactedClaims, disclosures, hashAlgOrOptions = "sha256") {
    const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
    const lookup = buildDisclosureLookup(disclosures, hashAlg);
    return reconstructMapInternal(redactedClaims, lookup, strict, 1);
  }
  function reconstructMapInternal(redactedClaims, lookup, strict, depth) {
    checkDepth(depth, strict);
    const resultClaims = /* @__PURE__ */ new Map();
    const remainingRedactedHashes = [];
    let redactedKeyHashes = null;
    for (const [key, value] of redactedClaims) {
      if (isRedactedKeysKey(key)) {
        redactedKeyHashes = value;
      } else {
        const { value: processedValue, redactedHashes } = reconstructValueRecursive(
          value,
          lookup,
          strict,
          depth + 1
        );
        resultClaims.set(key, processedValue);
        remainingRedactedHashes.push(...redactedHashes);
      }
    }
    if (redactedKeyHashes) {
      for (const hash of redactedKeyHashes) {
        const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
        const hexKey = Buffer2.from(hashBytes).toString("hex");
        const entry = lookup.get(hexKey);
        if (entry && entry.decoded.claimName !== void 0) {
          const { value: restoredValue, redactedHashes } = reconstructValueRecursive(
            entry.decoded.value,
            lookup,
            strict,
            depth + 1
          );
          remainingRedactedHashes.push(...redactedHashes);
          resultClaims.set(entry.decoded.claimName, restoredValue);
        } else {
          remainingRedactedHashes.push(hashBytes);
        }
      }
    }
    return { claims: resultClaims, redactedKeys: remainingRedactedHashes };
  }
  function reconstructArray(redactedArray, disclosures, hashAlgOrOptions = "sha256") {
    const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
    const lookup = buildDisclosureLookup(disclosures, hashAlg);
    return reconstructArrayRecursive(redactedArray, lookup, strict, 1);
  }
  function reconstructArrayRecursive(redactedArray, lookup, strict, depth) {
    checkDepth(depth, strict);
    const resultArray = [];
    const remainingRedactedHashes = [];
    for (const element of redactedArray) {
      if (isRedactedClaimElement(element)) {
        const rawContents = getRedactedElementContents(element);
        const hashBytes = rawContents instanceof Uint8Array ? rawContents : new Uint8Array(rawContents);
        const hexKey = Buffer2.from(hashBytes).toString("hex");
        const entry = lookup.get(hexKey);
        if (entry && entry.decoded.claimName === void 0 && !entry.decoded.isDecoy) {
          const { value: restoredValue, redactedHashes } = reconstructValueRecursive(
            entry.decoded.value,
            lookup,
            strict,
            depth + 1
          );
          remainingRedactedHashes.push(...redactedHashes);
          resultArray.push(restoredValue);
        } else {
          resultArray.push(element);
          remainingRedactedHashes.push(hashBytes);
        }
      } else {
        const { value: processedValue, redactedHashes } = reconstructValueRecursive(
          element,
          lookup,
          strict,
          depth + 1
        );
        resultArray.push(processedValue);
        remainingRedactedHashes.push(...redactedHashes);
      }
    }
    return { array: resultArray, redactedElements: remainingRedactedHashes };
  }
  function validateClaimsClean(claims, options = {}) {
    const { strict = false, allowRedacted = false } = options;
    const issues = [];
    validateValueClean(claims, issues, strict, 1, allowRedacted, "");
    return { isClean: issues.length === 0, issues };
  }
  function validateValueClean(value, issues, strict, depth, allowRedacted, path) {
    if (strict && depth > MAX_DEPTH) {
      issues.push(`Depth ${depth} exceeds maximum at ${path || "root"}`);
      return;
    }
    if (value instanceof Map) {
      for (const [key, val] of value) {
        const keyPath = path ? `${path}.${String(key)}` : String(key);
        if (isToBeRedacted(key)) {
          issues.push(`ToBeRedacted tag (58) found as key at ${keyPath}`);
        }
        if (isToBeDecoy(key)) {
          issues.push(`ToBeDecoy tag (61) found as key at ${keyPath}`);
        }
        if (!allowRedacted && isRedactedKeysKey(key)) {
          issues.push(`Redacted keys (simple 59) found at ${keyPath}`);
        }
        validateValueClean(val, issues, strict, depth + 1, allowRedacted, keyPath);
      }
    } else if (Array.isArray(value)) {
      for (let i3 = 0; i3 < value.length; i3++) {
        const elemPath = `${path}[${i3}]`;
        const elem = value[i3];
        if (isToBeRedacted(elem)) {
          issues.push(`ToBeRedacted tag (58) found at ${elemPath}`);
        }
        if (isToBeDecoy(elem)) {
          issues.push(`ToBeDecoy tag (61) found at ${elemPath}`);
        }
        if (!allowRedacted && isRedactedClaimElement(elem)) {
          issues.push(`RedactedClaimElement tag (60) found at ${elemPath}`);
        }
        if (!isToBeRedacted(elem) && !isToBeDecoy(elem) && !(isRedactedClaimElement(elem) && !allowRedacted)) {
          validateValueClean(elem, issues, strict, depth + 1, allowRedacted, elemPath);
        }
      }
    } else if (value instanceof i) {
      const tagPath = path ? `${path}.<tag ${value.tag}>` : `<tag ${value.tag}>`;
      if (isToBeRedacted(value)) {
        issues.push(`ToBeRedacted tag (58) found at ${tagPath}`);
      } else if (isToBeDecoy(value)) {
        issues.push(`ToBeDecoy tag (61) found at ${tagPath}`);
      } else if (!allowRedacted && isRedactedClaimElement(value)) {
        issues.push(`RedactedClaimElement tag (60) found at ${tagPath}`);
      } else {
        validateValueClean(value.contents, issues, strict, depth + 1, allowRedacted, tagPath);
      }
    }
  }
  function assertClaimsClean(claims, options = {}) {
    const result = validateClaimsClean(claims, options);
    if (!result.isClean) {
      throw new Error(`Claims contain SD-CWT artifacts:
${result.issues.join("\n")}`);
    }
  }

  // src/api.js
  var Issuer = {
    /**
     * Creates a signed SD-CWT from claims with optional redactable values.
     * 
     * Per spec Section 7: The payload MUST include a key confirmation element (cnf)
     * for the Holder's public key. Either sub or redacted sub MUST be present.
     * 
     * Claims can include:
     * - Regular claims: included directly in the token
     * - Redactable claims: wrapped with toBeRedacted(), stored as hashes with disclosures
     * - Decoys: wrapped with toBeDecoy(count), adds fake redacted entries
     * 
     * @param {Object} options - Issuance options
     * @param {Map} options.claims - Claims map, MUST contain cnf (8) claim with holder's public key
     * @param {Object} options.privateKey - Issuer's private key {d, x, y}
     * @param {string} [options.algorithm='ES256'] - Signing algorithm
     * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm for redactions
     * @param {string|Buffer} [options.kid] - Key identifier
     * @param {boolean} [options.strict=false] - If true, enforce max depth of 16 (per spec section 6.5)
     * @param {boolean} [options.claimsInProtectedHeader=false] - If true, place claims in CWT Claims header (15) instead of payload (per RFC 9597)
     * @returns {Promise<{token: Buffer, disclosures: Uint8Array[]}>} The signed SD-CWT and disclosures
     * 
     * @example
     * const claims = new Map([
     *   [1, 'issuer.example'],                    // iss - public
     *   [8, { 1: { 1: 2, -1: 1, -2: holderKey.x, -3: holderKey.y } }], // cnf - REQUIRED
     *   [toBeRedacted(500), 'sensitive-value'],   // redactable claim
     * ]);
     * 
     * const { token, disclosures } = await Issuer.issue({
     *   claims,
     *   privateKey: issuerKey.privateKey,
     * });
     */
    async issue({ claims, privateKey, algorithm = "ES256", hashAlgorithm = "sha256", kid, strict = false, claimsInProtectedHeader = false }) {
      if (!(claims instanceof Map)) {
        throw new Error("Claims must be a Map");
      }
      let hasCnf = false;
      let cnfIsRedacted = false;
      for (const key of claims.keys()) {
        if (key === ClaimKey.Cnf) {
          hasCnf = true;
          break;
        }
        if (isToBeRedacted(key) && getTagContents(key) === ClaimKey.Cnf) {
          hasCnf = true;
          cnfIsRedacted = true;
          break;
        }
      }
      if (!hasCnf) {
        throw new Error("Claims MUST include cnf (8) claim with Holder's public key (per spec Section 7)");
      }
      if (cnfIsRedacted) {
        throw new Error("cnf (8) claim MUST NOT be redacted (per spec Section 7)");
      }
      const { claims: processedClaims, disclosures } = processToBeRedacted(claims, { hashAlg: hashAlgorithm, strict });
      const customProtectedHeaders = /* @__PURE__ */ new Map();
      customProtectedHeaders.set(HeaderParam2.Typ, MediaType.SdCwt);
      if (disclosures.length > 0) {
        customProtectedHeaders.set(HeaderParam2.SdAlg, SdAlg.SHA256);
      }
      let payload;
      if (claimsInProtectedHeader) {
        customProtectedHeaders.set(HeaderParam2.CwtClaims, processedClaims);
        payload = new Uint8Array(0);
      } else {
        payload = Q(processedClaims);
      }
      const token = await sign3(payload, privateKey, {
        algorithm,
        kid,
        customProtectedHeaders: customProtectedHeaders.size > 0 ? customProtectedHeaders : void 0
      });
      return { token, disclosures };
    }
  };
  var Holder = {
    /**
     * Parses an SD-CWT token to extract the redacted claims structure.
     * Does not verify the signature.
     * 
     * @param {Buffer|Uint8Array} token - The SD-CWT token
     * @returns {{claims: Map, protectedHeaders: Map, unprotectedHeaders: Map}} Parsed token data
     */
    parse(token) {
      const { protectedHeaders, unprotectedHeaders } = getHeaders(token);
      const decoded = l5(token, cborDecodeOptions2);
      const coseArray = decoded.contents || decoded;
      const payloadBytes = coseArray[2];
      let claims;
      const cwtClaimsHeader = protectedHeaders.get(HeaderParam2.CwtClaims);
      if (cwtClaimsHeader instanceof Map) {
        claims = cwtClaimsHeader;
      } else if (payloadBytes && payloadBytes.length > 0) {
        claims = l5(payloadBytes, cborDecodeOptions2);
      } else {
        claims = /* @__PURE__ */ new Map();
      }
      return { claims, protectedHeaders, unprotectedHeaders };
    },
    /**
     * Selects which disclosures to present based on claim names/keys.
     * 
     * @param {Uint8Array[]} allDisclosures - All disclosures from the issuer
     * @param {Array<string|number>} claimNames - Claim names/keys to disclose
     * @returns {Uint8Array[]} Selected disclosures for presentation
     */
    selectDisclosures(allDisclosures, claimNames) {
      const selectedDisclosures = [];
      const claimNameSet = new Set(claimNames);
      for (const disclosure of allDisclosures) {
        const decoded = decodeDisclosure(disclosure);
        if (decoded.claimName !== void 0 && claimNameSet.has(decoded.claimName)) {
          selectedDisclosures.push(disclosure);
        }
        if (decoded.claimName === void 0 && !decoded.isDecoy) {
          if (claimNames.includes(decoded.value)) {
            selectedDisclosures.push(disclosure);
          }
        }
      }
      return selectedDisclosures;
    },
    /**
     * Creates a Key Binding Token (SD-KBT) presentation per spec Section 8.1.
     * 
     * The SD-KBT is a COSE_Sign1 signed by the Holder's private key that:
     * - Contains the SD-CWT (with disclosures) in the kcwt protected header
     * - Has aud (audience) claim REQUIRED per spec
     * - Has iat (issued at) claim REQUIRED per spec
     * - Optionally includes cnonce (client nonce)
     * 
     * @param {Object} options - Presentation options
     * @param {Buffer|Uint8Array} options.token - The original SD-CWT token
     * @param {Uint8Array[]} options.selectedDisclosures - Disclosures to include
     * @param {Object} options.holderPrivateKey - Holder's private key (matching cnf in SD-CWT)
     * @param {string} options.audience - The intended verifier (aud claim) - REQUIRED
     * @param {Uint8Array|Buffer} [options.nonce] - Optional nonce from verifier (cnonce claim)
     * @param {string} [options.algorithm='ES256'] - Signing algorithm
     * @returns {Promise<Buffer>} The signed SD-KBT presentation
     */
    async present({ token, selectedDisclosures, holderPrivateKey, audience, nonce, algorithm = "ES256" }) {
      if (!audience) {
        throw new Error("audience (aud) is REQUIRED in SD-KBT per spec Section 8.1");
      }
      if (!holderPrivateKey) {
        throw new Error("holderPrivateKey is REQUIRED to sign the SD-KBT");
      }
      const tokenBytes = Buffer2.isBuffer(token) ? new Uint8Array(token.buffer, token.byteOffset, token.length) : token instanceof Uint8Array ? token : new Uint8Array(token);
      const disclosureBytes = selectedDisclosures.map(
        (d5) => Buffer2.isBuffer(d5) ? new Uint8Array(d5.buffer, d5.byteOffset, d5.length) : d5 instanceof Uint8Array ? d5 : new Uint8Array(d5)
      );
      const sdCwtWithDisclosures = embedDisclosuresInToken(tokenBytes, disclosureBytes);
      const kbtPayload = /* @__PURE__ */ new Map([
        [ClaimKey.Aud, audience],
        [ClaimKey.Iat, Math.floor(Date.now() / 1e3)]
      ]);
      if (nonce) {
        const nonceBytes = Buffer2.isBuffer(nonce) ? new Uint8Array(nonce.buffer, nonce.byteOffset, nonce.length) : nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce);
        kbtPayload.set(ClaimKey.Cnonce, nonceBytes);
      }
      const kbtProtectedHeaders = /* @__PURE__ */ new Map([
        [HeaderParam2.Typ, MediaType.KbCwt],
        [HeaderParam2.Kcwt, sdCwtWithDisclosures]
      ]);
      const payloadEncoded = Q(kbtPayload);
      const kbt = await sign3(payloadEncoded, holderPrivateKey, {
        algorithm,
        customProtectedHeaders: kbtProtectedHeaders
      });
      return kbt;
    },
    /**
     * Filters disclosures by matching against redacted hashes in the claims.
     * Only returns disclosures that match actual redacted entries.
     * 
     * @param {Map} claims - The redacted claims from the token
     * @param {Uint8Array[]} disclosures - Disclosures to filter
     * @param {string} [hashAlgorithm='sha256'] - Hash algorithm used
     * @returns {Uint8Array[]} Valid disclosures that match redacted entries
     */
    filterValidDisclosures(claims, disclosures, hashAlgorithm = "sha256") {
      const redactedHashes = /* @__PURE__ */ new Set();
      collectRedactedHashes(claims, redactedHashes);
      const validDisclosures = [];
      for (const disclosure of disclosures) {
        const hash = hashDisclosure(disclosure, hashAlgorithm);
        const hexHash = Buffer2.from(hash).toString("hex");
        if (redactedHashes.has(hexHash)) {
          validDisclosures.push(disclosure);
        }
      }
      return validDisclosures;
    }
  };
  function copyBytes2(data) {
    if (!data || data.length === 0) {
      return data;
    }
    if (data instanceof Uint8Array) {
      const copy = new Uint8Array(data.length);
      copy.set(data);
      return copy;
    }
    if (ArrayBuffer.isView(data)) {
      const view = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      const copy = new Uint8Array(view.length);
      copy.set(view);
      return copy;
    }
    return data;
  }
  function embedDisclosuresInToken(token, disclosures) {
    const decoded = l5(token, cborDecodeOptions2);
    const coseArray = decoded.contents || decoded;
    const [protectedBytesRaw, unprotectedMap, payloadRaw, signatureRaw] = coseArray;
    const protectedBytes = copyBytes2(protectedBytesRaw);
    const payload = copyBytes2(payloadRaw);
    const signature = copyBytes2(signatureRaw);
    const newUnprotected = unprotectedMap instanceof Map ? new Map(unprotectedMap) : /* @__PURE__ */ new Map();
    newUnprotected.set(HeaderParam2.SdClaims, disclosures);
    const newCoseArray = [protectedBytes, newUnprotected, payload, signature];
    const encoded = Q(new i(18, newCoseArray));
    return Buffer2.isBuffer(encoded) ? new Uint8Array(encoded.buffer, encoded.byteOffset, encoded.length) : new Uint8Array(encoded);
  }
  function collectRedactedHashes(claims, hashSet) {
    if (claims instanceof Map) {
      for (const [key, value] of claims) {
        if (isRedactedKeysKey(key)) {
          for (const hash of value) {
            const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
            hashSet.add(Buffer2.from(hashBytes).toString("hex"));
          }
        } else if (value instanceof Map) {
          collectRedactedHashes(value, hashSet);
        } else if (Array.isArray(value)) {
          collectRedactedHashesFromArray(value, hashSet);
        }
      }
    }
  }
  function collectRedactedHashesFromArray(array, hashSet) {
    for (const element of array) {
      if (isRedactedClaimElement(element)) {
        const rawContents = getRedactedElementContents(element);
        const hashBytes = rawContents instanceof Uint8Array ? rawContents : new Uint8Array(rawContents);
        hashSet.add(Buffer2.from(hashBytes).toString("hex"));
      } else if (element instanceof Map && !element.has("tag")) {
        collectRedactedHashes(element, hashSet);
      } else if (Array.isArray(element)) {
        collectRedactedHashesFromArray(element, hashSet);
      }
    }
  }
  var Verifier = {
    /**
     * Verifies an SD-KBT (Key Binding Token) presentation per spec Section 9.
     * 
     * This function:
     * 1. Extracts the SD-CWT from the kcwt header in the SD-KBT
     * 2. Verifies the SD-CWT signature using the Issuer's public key
     * 3. Extracts the confirmation key (cnf) from the SD-CWT
     * 4. Verifies the SD-KBT signature using the confirmation key
     * 5. Validates audience matches the expected value
     * 6. Validates nonce if provided
     * 7. Reconstructs claims from disclosures
     * 
     * @param {Object} options - Verification options
     * @param {Buffer|Uint8Array} options.presentation - The SD-KBT presentation
     * @param {Object} options.issuerPublicKey - Issuer's public key {x, y}
     * @param {string} options.expectedAudience - The expected audience value (REQUIRED per spec Section 9)
     * @param {Uint8Array|Buffer} [options.expectedNonce] - Expected nonce if one was sent to Holder
     * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm used
     * @param {boolean} [options.strict=false] - If true, enforce max depth of 16 (per spec section 6.5)
     * @param {boolean} [options.requireClean=false] - If true, verify claims have no remaining SD-CWT artifacts
     * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], sdCwtClaims: Map, kbtPayload: Map, headers: Object}>} Verified result
     * @throws {Error} If verification fails
     * 
     * @example
     * const result = await Verifier.verify({
     *   presentation: kbt,
     *   issuerPublicKey: issuerKey.publicKey,
     *   expectedAudience: 'https://verifier.example/app',
     * });
     */
    async verify({ presentation, issuerPublicKey, expectedAudience, expectedNonce, hashAlgorithm = "sha256", strict = false, requireClean = false }) {
      if (!expectedAudience) {
        throw new Error("expectedAudience is REQUIRED per spec Section 9 Step 6");
      }
      const kbtHeaders = getHeaders(presentation);
      let sdCwtBytes = kbtHeaders.protectedHeaders.get(HeaderParam2.Kcwt);
      if (!sdCwtBytes) {
        throw new Error("Invalid SD-KBT: missing kcwt header parameter containing SD-CWT");
      }
      if (sdCwtBytes instanceof i) {
        sdCwtBytes = Q(sdCwtBytes);
      } else if (Array.isArray(sdCwtBytes) && sdCwtBytes.length === 4) {
        sdCwtBytes = Q(new i(18, sdCwtBytes));
      }
      if (Buffer2.isBuffer(sdCwtBytes)) {
        sdCwtBytes = new Uint8Array(sdCwtBytes.buffer, sdCwtBytes.byteOffset, sdCwtBytes.length);
      }
      const kbtTyp = kbtHeaders.protectedHeaders.get(HeaderParam2.Typ);
      if (kbtTyp !== MediaType.KbCwt) {
        throw new Error(`Invalid SD-KBT: typ must be "${MediaType.KbCwt}", got "${kbtTyp}"`);
      }
      const sdCwtPayloadBytes = await verify3(sdCwtBytes, issuerPublicKey);
      const sdCwtHeaders = getHeaders(sdCwtBytes);
      const cwtClaimsHeader = sdCwtHeaders.protectedHeaders.get(HeaderParam2.CwtClaims);
      let sdCwtClaims;
      if (cwtClaimsHeader instanceof Map) {
        sdCwtClaims = cwtClaimsHeader;
      } else if (sdCwtPayloadBytes && sdCwtPayloadBytes.length > 0) {
        sdCwtClaims = l5(sdCwtPayloadBytes, cborDecodeOptions2);
      } else {
        throw new Error("Invalid SD-CWT: no claims in payload or CWT Claims header (15)");
      }
      const cnfClaim = sdCwtClaims.get(ClaimKey.Cnf);
      if (!cnfClaim) {
        throw new Error("Invalid SD-CWT: missing cnf (8) claim with Holder confirmation key");
      }
      const holderPublicKey = extractPublicKeyFromCnf(cnfClaim);
      const kbtPayloadBytes = await verify3(presentation, holderPublicKey);
      const kbtPayload = l5(kbtPayloadBytes, cborDecodeOptions2);
      const kbtAud = kbtPayload.get(ClaimKey.Aud);
      if (!kbtAud) {
        throw new Error("Invalid SD-KBT: missing aud (3) claim");
      }
      const kbtIat = kbtPayload.get(ClaimKey.Iat);
      if (kbtIat === void 0) {
        throw new Error("Invalid SD-KBT: missing iat (6) claim");
      }
      if (kbtAud !== expectedAudience) {
        throw new Error(`Audience mismatch: expected "${expectedAudience}", got "${kbtAud}"`);
      }
      const sdCwtAud = sdCwtClaims.get(ClaimKey.Aud);
      if (sdCwtAud && sdCwtAud !== expectedAudience) {
        throw new Error(`SD-CWT audience mismatch: expected "${expectedAudience}", got "${sdCwtAud}"`);
      }
      if (expectedNonce) {
        const kbtNonce = kbtPayload.get(ClaimKey.Cnonce);
        if (!kbtNonce) {
          throw new Error("Expected nonce (cnonce) but none present in SD-KBT");
        }
        const expectedBytes = Buffer2.isBuffer(expectedNonce) ? expectedNonce : Buffer2.from(expectedNonce);
        const actualBytes = Buffer2.isBuffer(kbtNonce) ? kbtNonce : Buffer2.from(kbtNonce);
        if (!expectedBytes.equals(actualBytes)) {
          throw new Error("Nonce mismatch");
        }
      }
      const disclosures = sdCwtHeaders.unprotectedHeaders.get(HeaderParam2.SdClaims) || [];
      const validatedDisclosures = validateDisclosures(sdCwtClaims, disclosures, hashAlgorithm);
      const { claims, redactedKeys } = reconstructClaims(
        sdCwtClaims,
        validatedDisclosures,
        { hashAlg: hashAlgorithm, strict }
      );
      if (requireClean) {
        assertClaimsClean(claims, { strict });
        if (redactedKeys.length > 0) {
          throw new Error(`Claims contain SD-CWT artifacts:
${redactedKeys.length} undisclosed redacted key(s) remain`);
        }
      }
      return {
        claims,
        redactedKeys,
        sdCwtClaims,
        // Original SD-CWT claims (for inspection)
        kbtPayload,
        // SD-KBT payload (aud, iat, cnonce)
        headers: {
          sdCwt: {
            protected: sdCwtHeaders.protectedHeaders,
            unprotected: sdCwtHeaders.unprotectedHeaders
          },
          kbt: {
            protected: kbtHeaders.protectedHeaders,
            unprotected: kbtHeaders.unprotectedHeaders
          }
        }
      };
    },
    /**
     * Verifies a raw SD-CWT token with separate disclosures (no key binding).
     * 
     * WARNING: This method does NOT verify key binding. Per spec, SD-CWT requires
     * key binding (SD-KBT). Use verify() for spec-compliant verification.
     * 
     * This method is provided for testing and backwards compatibility only.
     * 
     * @param {Object} options - Verification options
     * @param {Buffer|Uint8Array} options.token - The SD-CWT token
     * @param {Uint8Array[]} options.disclosures - Disclosures to apply
     * @param {Object} options.publicKey - Issuer's public key {x, y}
     * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm used
     * @param {boolean} [options.strict=false] - If true, enforce max depth of 16
     * @param {boolean} [options.requireClean=false] - If true, verify claims have no remaining SD-CWT artifacts
     * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], headers: Object}>} Verified result
     * @deprecated Use verify() with proper SD-KBT presentation for spec compliance
     */
    async verifyWithoutKeyBinding({ token, disclosures, publicKey, hashAlgorithm = "sha256", strict = false, requireClean = false }) {
      const payloadBytes = await verify3(token, publicKey);
      const redactedClaims = l5(payloadBytes, cborDecodeOptions2);
      const validatedDisclosures = validateDisclosures(redactedClaims, disclosures, hashAlgorithm);
      const { claims, redactedKeys } = reconstructClaims(
        redactedClaims,
        validatedDisclosures,
        { hashAlg: hashAlgorithm, strict }
      );
      if (requireClean) {
        assertClaimsClean(claims, { strict });
        if (redactedKeys.length > 0) {
          throw new Error(`Claims contain SD-CWT artifacts:
${redactedKeys.length} undisclosed redacted key(s) remain`);
        }
      }
      const { protectedHeaders, unprotectedHeaders } = getHeaders(token);
      return {
        claims,
        redactedKeys,
        headers: {
          protected: protectedHeaders,
          unprotected: unprotectedHeaders
        }
      };
    }
  };
  function extractPublicKeyFromCnf(cnfClaim) {
    let coseKey;
    if (cnfClaim instanceof Map) {
      coseKey = cnfClaim.get(1);
    } else if (typeof cnfClaim === "object") {
      coseKey = cnfClaim[1];
    }
    if (!coseKey) {
      throw new Error("Invalid cnf claim: missing COSE_Key (key 1)");
    }
    let x4, y6;
    if (coseKey instanceof Map) {
      x4 = coseKey.get(-2);
      y6 = coseKey.get(-3);
    } else if (typeof coseKey === "object") {
      x4 = coseKey[-2] || coseKey["-2"];
      y6 = coseKey[-3] || coseKey["-3"];
    }
    if (!x4 || !y6) {
      throw new Error("Invalid COSE_Key in cnf: missing x (-2) or y (-3) coordinates");
    }
    return { x: x4, y: y6 };
  }
  function validateDisclosures(redactedClaims, disclosures, hashAlgorithm) {
    const redactedHashes = /* @__PURE__ */ new Set();
    collectRedactedHashes(redactedClaims, redactedHashes);
    const validDisclosures = [];
    for (const disclosure of disclosures) {
      const hash = hashDisclosure(disclosure, hashAlgorithm);
      const hexHash = Buffer2.from(hash).toString("hex");
      if (!redactedHashes.has(hexHash)) {
        console.warn("Warning: Disclosure does not match any redacted entry");
        continue;
      }
      validDisclosures.push(disclosure);
    }
    return validDisclosures;
  }
  var Utils = {
    /**
     * Decodes a disclosure to inspect its contents.
     * 
     * @param {Uint8Array} disclosure - The disclosure to decode
     * @returns {{salt: Uint8Array, value: any, claimName?: string|number, isDecoy?: boolean}}
     */
    decodeDisclosure,
    /**
     * Computes the hash of a disclosure.
     * 
     * @param {Uint8Array} disclosure - The disclosure
     * @param {string} [algorithm='sha256'] - Hash algorithm
     * @returns {Uint8Array} The hash
     */
    hashDisclosure,
    /**
     * Checks if a claims map has any redacted entries.
     * 
     * @param {Map} claims - The claims to check
     * @returns {boolean} True if there are redacted entries
     */
    hasRedactions(claims) {
      for (const [key, value] of claims) {
        if (isRedactedKeysKey(key)) {
          return true;
        }
        if (value instanceof Map && this.hasRedactions(value)) {
          return true;
        }
        if (Array.isArray(value)) {
          for (const element of value) {
            if (isRedactedClaimElement(element)) {
              return true;
            }
            if (element instanceof Map && this.hasRedactions(element)) {
              return true;
            }
          }
        }
      }
      return false;
    },
    /**
     * Counts the number of redacted entries in claims.
     * 
     * @param {Map} claims - The claims to analyze
     * @returns {{mapKeys: number, arrayElements: number, total: number}} Redaction counts
     */
    countRedactions(claims) {
      let mapKeys = 0;
      let arrayElements = 0;
      function countInMap(map) {
        for (const [key, value] of map) {
          if (isRedactedKeysKey(key)) {
            mapKeys += value.length;
          } else if (value instanceof Map) {
            countInMap(value);
          } else if (Array.isArray(value)) {
            countInArray(value);
          }
        }
      }
      function countInArray(array) {
        for (const element of array) {
          if (isRedactedClaimElement(element)) {
            arrayElements++;
          } else if (element instanceof Map) {
            countInMap(element);
          } else if (Array.isArray(element)) {
            countInArray(element);
          }
        }
      }
      countInMap(claims);
      return { mapKeys, arrayElements, total: mapKeys + arrayElements };
    },
    /**
     * Lists all claim names/keys that are currently redacted.
     * Only works for map key redactions, not array elements.
     * Requires disclosures to determine the original claim names.
     * 
     * @param {Uint8Array[]} disclosures - All available disclosures
     * @returns {Array<string|number>} List of redacted claim names
     */
    getDisclosableClaimNames(disclosures) {
      const names = [];
      for (const disclosure of disclosures) {
        const decoded = decodeDisclosure(disclosure);
        if (decoded.claimName !== void 0) {
          names.push(decoded.claimName);
        }
      }
      return names;
    },
    /**
     * CBOR decode options that ensure Maps are decoded properly.
     */
    cborDecodeOptions: cborDecodeOptions2
  };

  // src/edn.js
  var Buffer3 = globalThis.Buffer;
  var Hex = {
    /**
     * Encode bytes to hex string
     * @param {Uint8Array|Buffer} bytes 
     * @returns {string}
     */
    encode(bytes) {
      if (!bytes) return "";
      const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      return Array.from(arr).map((b4) => b4.toString(16).padStart(2, "0")).join("");
    },
    /**
     * Decode hex string to Uint8Array
     * @param {string} hex 
     * @returns {Uint8Array}
     */
    decode(hex) {
      if (!hex) return new Uint8Array(0);
      const clean = hex.replace(/\s/g, "");
      const bytes = new Uint8Array(clean.length / 2);
      for (let i3 = 0; i3 < bytes.length; i3++) {
        bytes[i3] = parseInt(clean.substr(i3 * 2, 2), 16);
      }
      return bytes;
    }
  };
  var CWT_CLAIM_NAMES = {
    1: "iss",
    2: "sub",
    3: "aud",
    4: "exp",
    5: "nbf",
    6: "iat",
    7: "cti",
    8: "cnf",
    39: "cnonce"
  };
  function getClaimComment(key) {
    const name = CWT_CLAIM_NAMES[key];
    return name ? `/ ${name} / ` : "";
  }
  function getRedactionComment(key) {
    if (key instanceof i && key.tag === 58) {
      if (typeof key.contents === "number") {
        return { isRedacted: true, comment: "/ to be redacted / " };
      }
      return { isRedacted: true, comment: "/ to be redacted / " };
    }
    return { isRedacted: false, comment: "" };
  }
  var EDN = {
    /**
     * Convert a JavaScript value to EDN string
     * @param {any} value 
     * @param {object} options
     * @param {number} options.indent - spaces per indent level (default 2)
     * @returns {string}
     */
    stringify(value, options = {}) {
      const indent = options.indent ?? 2;
      return ednStringify(value, indent, 0);
    },
    /**
     * Parse an EDN string into JavaScript values
     * Uses cbor2.Tag for CBOR tags, Map for objects, arrays for arrays
     * @param {string} ednString 
     * @returns {any}
     */
    parse(ednString) {
      return parseEdn(ednString);
    },
    /**
     * Format a CWT claims Map to EDN with named comments for known claims
     * Comments are only added at the top level
     * @param {Map} claims 
     * @returns {string}
     */
    formatClaims(claims) {
      return formatMapWithComments(claims, 0, true);
    }
  };
  function ednStringify(value, indent, depth) {
    const padChar = " ".repeat(indent);
    const pad = padChar.repeat(depth);
    const pad1 = padChar.repeat(depth + 1);
    if (value === null) {
      return "null";
    }
    if (value === void 0) {
      return "undefined";
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    if (typeof value === "number") {
      return String(value);
    }
    if (typeof value === "string") {
      return JSON.stringify(value);
    }
    if (value instanceof Uint8Array || Buffer3 && Buffer3.isBuffer && Buffer3.isBuffer(value)) {
      const hex = Hex.encode(value);
      if (hex.length <= 64) {
        return `h'${hex}'`;
      }
      const lines = [];
      for (let i3 = 0; i3 < hex.length; i3 += 64) {
        lines.push(hex.slice(i3, i3 + 64));
      }
      return `h'${lines.join("\n" + pad1)}'`;
    }
    if (value instanceof i) {
      const tagContent = ednStringify(value.contents, indent, depth);
      return `${value.tag}(${tagContent})`;
    }
    if (value && typeof value === "object" && value.type === "simple") {
      return `simple(${value.value})`;
    }
    if (value instanceof Map) {
      if (value.size === 0) {
        return "{}";
      }
      const entries = [];
      for (const [k4, v2] of value) {
        const keyStr = ednStringify(k4, indent, depth + 1);
        const valStr = ednStringify(v2, indent, depth + 1);
        entries.push(`${pad1}${keyStr}: ${valStr}`);
      }
      return `{
${entries.join(",\n")}
${pad}}`;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) {
        return "[]";
      }
      const items = value.map((v2) => `${pad1}${ednStringify(v2, indent, depth + 1)}`);
      return `[
${items.join(",\n")}
${pad}]`;
    }
    if (typeof value === "object") {
      const keys = Object.keys(value);
      if (keys.length === 0) {
        return "{}";
      }
      const entries = keys.map((k4) => {
        const valStr = ednStringify(value[k4], indent, depth + 1);
        return `${pad1}"${k4}": ${valStr}`;
      });
      return `{
${entries.join(",\n")}
${pad}}`;
    }
    return String(value);
  }
  function formatMapWithComments(map, depth, addComments = false) {
    if (!(map instanceof Map) || map.size === 0) {
      return "{}";
    }
    const pad = "  ".repeat(depth);
    const pad1 = "  ".repeat(depth + 1);
    const entries = [];
    for (const [key, value] of map) {
      let comment = "";
      const redaction = getRedactionComment(key);
      if (redaction.isRedacted) {
        comment = redaction.comment;
      } else if (addComments && typeof key === "number") {
        comment = getClaimComment(key);
      }
      const keyStr = formatValueWithComments(key, depth + 1);
      const valStr = formatValueWithComments(value, depth + 1);
      entries.push(`${pad1}${comment}${keyStr}: ${valStr}`);
    }
    return `{
${entries.join(",\n")}
${pad}}`;
  }
  function formatValueWithComments(value, depth) {
    const pad = "  ".repeat(depth);
    const pad1 = "  ".repeat(depth + 1);
    if (value === null) return "null";
    if (value === void 0) return "undefined";
    if (typeof value === "boolean") return value ? "true" : "false";
    if (typeof value === "number") return String(value);
    if (typeof value === "string") return JSON.stringify(value);
    if (value instanceof Uint8Array || Buffer3 && Buffer3.isBuffer && Buffer3.isBuffer(value)) {
      const hex = Hex.encode(value);
      if (hex.length <= 64) {
        return `h'${hex}'`;
      }
      const lines = [];
      for (let i3 = 0; i3 < hex.length; i3 += 64) {
        lines.push(hex.slice(i3, i3 + 64));
      }
      return `h'${lines.join("\n" + pad1)}'`;
    }
    if (value instanceof i) {
      const tagContent = formatValueWithComments(value.contents, depth);
      return `${value.tag}(${tagContent})`;
    }
    if (value && typeof value === "object" && value.type === "simple") {
      return `simple(${value.value})`;
    }
    if (value instanceof Map) {
      return formatMapWithComments(value, depth, false);
    }
    if (Array.isArray(value)) {
      if (value.length === 0) return "[]";
      const items = value.map((v2) => `${pad1}${formatValueWithComments(v2, depth + 1)}`);
      return `[
${items.join(",\n")}
${pad}]`;
    }
    if (typeof value === "object") {
      const keys = Object.keys(value);
      if (keys.length === 0) return "{}";
      const entries = keys.map((k4) => {
        const valStr = formatValueWithComments(value[k4], depth + 1);
        return `${pad1}"${k4}": ${valStr}`;
      });
      return `{
${entries.join(",\n")}
${pad}}`;
    }
    return String(value);
  }
  function parseEdn(ednString) {
    let pos = 0;
    const src = ednString;
    function skipWhitespace() {
      while (pos < src.length) {
        const ch = src[pos];
        if (ch === " " || ch === "	" || ch === "\n" || ch === "\r") {
          pos++;
        } else {
          break;
        }
      }
    }
    function skipComment() {
      if (pos < src.length && src[pos] === "/") {
        pos++;
        while (pos < src.length) {
          if (src[pos] === "/" && pos > 0 && src[pos - 1] === " ") {
            pos++;
            break;
          }
          pos++;
        }
        return true;
      }
      return false;
    }
    function skipWhitespaceAndComments() {
      while (pos < src.length) {
        skipWhitespace();
        if (pos < src.length && src[pos] === "/") {
          skipComment();
        } else {
          break;
        }
      }
    }
    function parseValue() {
      skipWhitespaceAndComments();
      if (pos >= src.length) throw new Error("Unexpected end of input");
      const ch = src[pos];
      if (ch === '"') {
        return parseString();
      }
      if (ch === "{") {
        return parseMap();
      }
      if (ch === "[") {
        return parseArray();
      }
      if (/\d/.test(ch)) {
        return parseNumberOrTag();
      }
      if (/[a-z]/.test(ch)) {
        return parseKeywordOrHex();
      }
      if (ch === "-") {
        return parseNumber();
      }
      throw new Error(`Unexpected character '${ch}' at position ${pos}`);
    }
    function parseString() {
      pos++;
      let result = "";
      while (pos < src.length && src[pos] !== '"') {
        if (src[pos] === "\\") {
          pos++;
          if (pos >= src.length) throw new Error("Unterminated string");
          const escape = src[pos];
          if (escape === "n") result += "\n";
          else if (escape === "t") result += "	";
          else if (escape === "r") result += "\r";
          else if (escape === '"') result += '"';
          else if (escape === "\\") result += "\\";
          else result += escape;
        } else {
          result += src[pos];
        }
        pos++;
      }
      if (pos >= src.length) throw new Error("Unterminated string");
      pos++;
      return result;
    }
    function parseNumber() {
      const start = pos;
      if (src[pos] === "-") pos++;
      while (pos < src.length && /\d/.test(src[pos])) pos++;
      if (pos < src.length && src[pos] === ".") {
        pos++;
        while (pos < src.length && /\d/.test(src[pos])) pos++;
      }
      const numStr = src.slice(start, pos);
      return numStr.includes(".") ? parseFloat(numStr) : parseInt(numStr, 10);
    }
    function parseNumberOrTag() {
      const start = pos;
      while (pos < src.length && /\d/.test(src[pos])) pos++;
      let hasDecimal = false;
      if (pos < src.length && src[pos] === ".") {
        if (pos + 1 < src.length && /\d/.test(src[pos + 1])) {
          hasDecimal = true;
          pos++;
          while (pos < src.length && /\d/.test(src[pos])) pos++;
        }
      }
      const numStr = src.slice(start, pos);
      if (hasDecimal) {
        return parseFloat(numStr);
      }
      skipWhitespaceAndComments();
      if (pos < src.length && src[pos] === "(") {
        pos++;
        const tagNumber = parseInt(numStr, 10);
        const content = parseValue();
        skipWhitespaceAndComments();
        if (src[pos] !== ")") throw new Error("Expected ) after tag content");
        pos++;
        return new i(tagNumber, content);
      }
      return parseInt(numStr, 10);
    }
    function parseKeywordOrHex() {
      if (src[pos] === "h" && pos + 1 < src.length && src[pos + 1] === "'") {
        return parseHexBytes();
      }
      if (src.slice(pos, pos + 7) === "simple(") {
        return parseSimple();
      }
      const start = pos;
      while (pos < src.length && /[a-z_]/.test(src[pos])) pos++;
      const keyword = src.slice(start, pos);
      if (keyword === "true") return true;
      if (keyword === "false") return false;
      if (keyword === "null") return null;
      throw new Error(`Unknown keyword: ${keyword}`);
    }
    function parseHexBytes() {
      pos += 2;
      const start = pos;
      while (pos < src.length && src[pos] !== "'") pos++;
      const hexStr = src.slice(start, pos).replace(/\s/g, "");
      pos++;
      return Hex.decode(hexStr);
    }
    function parseSimple() {
      pos += 7;
      skipWhitespaceAndComments();
      const valueStr = [];
      while (pos < src.length && /\d/.test(src[pos])) {
        valueStr.push(src[pos]);
        pos++;
      }
      skipWhitespaceAndComments();
      if (src[pos] !== ")") throw new Error("Expected ) after simple value");
      pos++;
      return { type: "simple", value: parseInt(valueStr.join(""), 10) };
    }
    function parseMap() {
      pos++;
      const result = /* @__PURE__ */ new Map();
      while (true) {
        skipWhitespaceAndComments();
        if (pos >= src.length) throw new Error("Unterminated map");
        if (src[pos] === "}") {
          pos++;
          break;
        }
        const key = parseValue();
        skipWhitespaceAndComments();
        if (src[pos] !== ":") throw new Error(`Expected ':' after map key at position ${pos}, got '${src[pos]}'`);
        pos++;
        const value = parseValue();
        result.set(key, value);
        skipWhitespaceAndComments();
        if (src[pos] === ",") pos++;
      }
      return result;
    }
    function parseArray() {
      pos++;
      const result = [];
      while (true) {
        skipWhitespaceAndComments();
        if (pos >= src.length) throw new Error("Unterminated array");
        if (src[pos] === "]") {
          pos++;
          break;
        }
        result.push(parseValue());
        skipWhitespaceAndComments();
        if (src[pos] === ",") pos++;
      }
      return result;
    }
    return parseValue();
  }

  // src/browser.js
  function formatClaims(claims) {
    return EDN.formatClaims(claims);
  }
  return __toCommonJS(browser_exports);
})();
//# sourceMappingURL=sd-cwt.js.map
