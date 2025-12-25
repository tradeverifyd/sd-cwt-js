/**
 * Minimal Buffer shim for browser compatibility
 * 
 * Provides the subset of Buffer functionality needed by sd-cwt
 */

class BufferShim extends Uint8Array {
  constructor(input, byteOffsetOrEncoding, byteLength) {
    // Handle the 3-argument case: new BufferShim(arrayBuffer, byteOffset, byteLength)
    if (input instanceof ArrayBuffer && typeof byteOffsetOrEncoding === 'number') {
      super(input, byteOffsetOrEncoding, byteLength);
    } else if (typeof input === 'number') {
      super(input);
    } else if (typeof input === 'string') {
      const bytes = BufferShim._fromString(input, byteOffsetOrEncoding);
      super(bytes);
    } else if (input instanceof ArrayBuffer) {
      super(input);
    } else if (ArrayBuffer.isView(input)) {
      // Create a copy of the TypedArray data
      // Use super([...]) to pass the data directly
      super([...new Uint8Array(input.buffer, input.byteOffset, input.byteLength)]);
    } else if (Array.isArray(input)) {
      super(input);
    } else if (input && typeof input === 'object' && 'type' in input && input.type === 'Buffer') {
      // Handle Buffer.toJSON() format: { type: 'Buffer', data: [...] }
      super(input.data);
    } else {
      super(input || 0);
    }
  }

  static _fromString(str, encoding = 'utf8') {
    if (encoding === 'hex') {
      const hex = str.replace(/\s/g, '');
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
      }
      return bytes;
    } else if (encoding === 'base64' || encoding === 'base64url') {
      let base64 = str;
      if (encoding === 'base64url') {
        base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
        const pad = base64.length % 4;
        if (pad) {
          base64 += '='.repeat(4 - pad);
        }
      }
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } else {
      // utf8
      return new TextEncoder().encode(str);
    }
  }

  static from(input, encoding) {
    if (typeof input === 'string') {
      return new BufferShim(BufferShim._fromString(input, encoding));
    }
    if (input instanceof ArrayBuffer) {
      return new BufferShim(input);
    }
    if (ArrayBuffer.isView(input)) {
      // Use the constructor which now handles ArrayBufferView by copying
      return new BufferShim(input);
    }
    if (Array.isArray(input)) {
      return new BufferShim(input);
    }
    if (input && typeof input === 'object' && 'type' in input && input.type === 'Buffer') {
      return new BufferShim(input.data);
    }
    return new BufferShim(input);
  }

  static isBuffer(obj) {
    return obj instanceof BufferShim || 
           (obj instanceof Uint8Array && obj.constructor.name === 'Buffer');
  }

  static alloc(size, fill = 0) {
    const buf = new BufferShim(size);
    if (fill !== 0) {
      buf.fill(fill);
    }
    return buf;
  }

  static allocUnsafe(size) {
    return new BufferShim(size);
  }

  static concat(list, totalLength) {
    if (totalLength === undefined) {
      totalLength = list.reduce((acc, buf) => acc + buf.length, 0);
    }
    const result = new BufferShim(totalLength);
    let offset = 0;
    for (const buf of list) {
      result.set(buf, offset);
      offset += buf.length;
    }
    return result;
  }

  toString(encoding = 'utf8') {
    if (encoding === 'hex') {
      return Array.from(this).map(b => b.toString(16).padStart(2, '0')).join('');
    } else if (encoding === 'base64') {
      let binary = '';
      for (let i = 0; i < this.length; i++) {
        binary += String.fromCharCode(this[i]);
      }
      return btoa(binary);
    } else if (encoding === 'base64url') {
      let binary = '';
      for (let i = 0; i < this.length; i++) {
        binary += String.fromCharCode(this[i]);
      }
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } else {
      // utf8
      return new TextDecoder().decode(this);
    }
  }

  toJSON() {
    return {
      type: 'Buffer',
      data: Array.from(this),
    };
  }

  slice(start, end) {
    return new BufferShim(this.subarray(start, end));
  }

  copy(target, targetStart = 0, sourceStart = 0, sourceEnd = this.length) {
    const source = this.subarray(sourceStart, sourceEnd);
    target.set(source, targetStart);
    return source.length;
  }

  equals(other) {
    if (this.length !== other.length) return false;
    for (let i = 0; i < this.length; i++) {
      if (this[i] !== other[i]) return false;
    }
    return true;
  }

  compare(other) {
    const len = Math.min(this.length, other.length);
    for (let i = 0; i < len; i++) {
      if (this[i] < other[i]) return -1;
      if (this[i] > other[i]) return 1;
    }
    if (this.length < other.length) return -1;
    if (this.length > other.length) return 1;
    return 0;
  }

  readUInt32BE(offset = 0) {
    return (
      (this[offset] << 24) |
      (this[offset + 1] << 16) |
      (this[offset + 2] << 8) |
      this[offset + 3]
    ) >>> 0;
  }

  writeUInt32BE(value, offset = 0) {
    this[offset] = (value >>> 24) & 0xff;
    this[offset + 1] = (value >>> 16) & 0xff;
    this[offset + 2] = (value >>> 8) & 0xff;
    this[offset + 3] = value & 0xff;
    return offset + 4;
  }
}

// Make BufferShim inherit all Uint8Array static properties
Object.getOwnPropertyNames(Uint8Array).forEach(prop => {
  if (!(prop in BufferShim) && typeof Uint8Array[prop] === 'function') {
    BufferShim[prop] = Uint8Array[prop];
  }
});

export const Buffer = BufferShim;
export default BufferShim;

