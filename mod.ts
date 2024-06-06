import type { SerializableHash } from "npm:@stablelib/hash@1.0.1";
import { readUint32BE, writeUint32BE } from "npm:@stablelib/binary@1.0.1";
import { wipe } from "npm:@stablelib/wipe@1.0.1";
import { hmac } from "npm:@stablelib/hmac@1.0.1";
import arrayBufferToHex from "npm:array-buffer-to-hex@1.0.0";

export const DIGEST_LENGTH = 20;
export const BLOCK_SIZE = 64;

export class SHA1 implements SerializableHash {
    readonly digestLength: number = DIGEST_LENGTH;
    readonly blockSize: number = BLOCK_SIZE;

    protected _state: Int32Array = new Int32Array(5);
    private _temp = new Int32Array(80);
    private _buffer = new Uint8Array(128);
    private _bufferLength = 0;
    private _bytesHashed = 0;
    private _finished = false;

    constructor() {
        this.reset();
    }

    protected _initState() {
        this._state[0] = 0x67452301;
        this._state[1] = 0xefcdab89;
        this._state[2] = 0x98badcfe;
        this._state[3] = 0x10325476;
        this._state[4] = 0xc3d2e1f0;
    }

    /**
     * Resets hash state making it possible
     * to re-use this instance to hash other data.
     */
    reset(): this {
        this._initState();
        this._bufferLength = 0;
        this._bytesHashed = 0;
        this._finished = false;
        return this;
    }

    /**
     * Cleans internal buffers and resets hash state.
     */
    clean() {
        wipe(this._buffer);
        wipe(this._temp);
        this.reset();
    }

    /**
     * Updates hash state with the given data.
     *
     * Throws error when trying to update already finalized hash:
     * instance must be reset to update it again.
     */
    update(data: Uint8Array, dataLength: number = data.length): this {
        if (this._finished) {
            throw new Error("SHA1: can't update because hash was finished.");
        }
        let dataPos = 0;
        this._bytesHashed += dataLength;
        if (this._bufferLength > 0) {
            while (this._bufferLength < this.blockSize && dataLength > 0) {
                this._buffer[this._bufferLength++] = data[dataPos++];
                dataLength--;
            }
            if (this._bufferLength === this.blockSize) {
                hashBlocks(
                    this._temp,
                    this._state,
                    this._buffer,
                    0,
                    this.blockSize,
                );
                this._bufferLength = 0;
            }
        }
        if (dataLength >= this.blockSize) {
            dataPos = hashBlocks(
                this._temp,
                this._state,
                data,
                dataPos,
                dataLength,
            );
            dataLength %= this.blockSize;
        }
        while (dataLength > 0) {
            this._buffer[this._bufferLength++] = data[dataPos++];
            dataLength--;
        }
        return this;
    }

    /**
     * Finalizes hash state and puts hash into out.
     * If hash was already finalized, puts the same value.
     */
    finish(out: Uint8Array): this {
        if (!this._finished) {
            const bytesHashed = this._bytesHashed;
            const left = this._bufferLength;
            const bitLenHi = (bytesHashed / 0x20000000) | 0;
            const bitLenLo = bytesHashed << 3;
            const padLength = (bytesHashed % 64 < 56) ? 64 : 128;

            this._buffer[left] = 0x80;
            for (let i = left + 1; i < padLength - 8; i++) {
                this._buffer[i] = 0;
            }
            writeUint32BE(bitLenHi, this._buffer, padLength - 8);
            writeUint32BE(bitLenLo, this._buffer, padLength - 4);

            hashBlocks(this._temp, this._state, this._buffer, 0, padLength);
            this._finished = true;
        }

        for (let i = 0; i < this.digestLength / 4; i++) {
            writeUint32BE(this._state[i], out, i * 4);
        }

        return this;
    }

    /**
     * Returns the final hash digest.
     */
    digest(): Uint8Array {
        const out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }

    /**
     * Returns the final hash digesh as hex format.
     */
    digest_hex(): string {
        return arrayBufferToHex(this.digest().buffer);
    }

    /**
     * Function useful for HMAC/PBKDF2 optimization.
     * Returns hash state to be used with restoreState().
     * Only chain value is saved, not buffers or other
     * state variables.
     */
    saveState(): SavedState {
        if (this._finished) {
            throw new Error("SHA256: cannot save finished state");
        }
        return {
            state: new Int32Array(this._state),
            buffer: this._bufferLength > 0
                ? new Uint8Array(this._buffer)
                : undefined,
            bufferLength: this._bufferLength,
            bytesHashed: this._bytesHashed,
        };
    }

    /**
     * Function useful for HMAC/PBKDF2 optimization.
     * Restores state saved by saveState() and sets bytesHashed
     * to the given value.
     */
    restoreState(savedState: SavedState): this {
        this._state.set(savedState.state);
        this._bufferLength = savedState.bufferLength;
        if (savedState.buffer) {
            this._buffer.set(savedState.buffer);
        }
        this._bytesHashed = savedState.bytesHashed;
        this._finished = false;
        return this;
    }

    /**
     * Cleans state returned by saveState().
     */
    cleanSavedState(savedState: SavedState) {
        wipe(savedState.state);
        if (savedState.buffer) {
            wipe(savedState.buffer);
        }
        savedState.bufferLength = 0;
        savedState.bytesHashed = 0;
    }
}

export type SavedState = {
    state: Int32Array;
    buffer: Uint8Array | undefined;
    bufferLength: number;
    bytesHashed: number;
};

function leftrotate(x: number, c: number) {
    return (x << c) | (x >>> (32 - c));
}

function safeAdd(x: number, y: number): number {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
}

function hashBlocks(
    w: Int32Array,
    v: Int32Array,
    p: Uint8Array,
    pos: number,
    len: number,
): number {
    while (len >= 64) {
        let a = v[0], b = v[1], c = v[2], d = v[3], e = v[4];
        for (let i = 0; i < 16; i++) {
            const j = pos + i * 4;
            w[i] = readUint32BE(p, j);
        }
        for (let i = 16; i < 80; i++) {
            w[i] = leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        for (let i = 0; i < 80; i++) {
            let f: number = 0;
            let k: number = 0;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else if (i < 80) {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            const temp = safeAdd(
                leftrotate(a, 5),
                safeAdd(f, safeAdd(e, safeAdd(k, w[i]))),
            );
            e = d;
            d = c;
            c = leftrotate(b, 30);
            b = a;
            a = temp;
        }

        v[0] = safeAdd(v[0], a);
        v[1] = safeAdd(v[1], b);
        v[2] = safeAdd(v[2], c);
        v[3] = safeAdd(v[3], d);
        v[4] = safeAdd(v[4], e);

        pos += 64;
        len -= 64;
    }
    return pos;
}

export function hash(data: Uint8Array): Uint8Array {
    const h = new SHA1();
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}

export function sha1(s: string): string {
    const enc = new TextEncoder();
    const arr = enc.encode(s);
    const h = hash(arr);
    return arrayBufferToHex(h.buffer);
}

export function hashWithHmac(key: Uint8Array, data: Uint8Array): Uint8Array {
    return hmac(SHA1, key, data);
}

export function HmacSHA1(key: string, data: string): string {
    const enc = new TextEncoder();
    const k = enc.encode(key);
    const d = enc.encode(data);
    const h = hashWithHmac(k, d);
    return arrayBufferToHex(h.buffer);
}
