import { PrivKey } from "../priv-key";
import { PubKey } from "../pub-key";
import { PubKeySecp256k1 } from "./pub-key";
import * as crypto from "crypto";
import * as secp256k1 from "tiny-secp256k1";
/**
 * secp256k1
 */
export class PrivKeySecp256k1 implements PrivKey {
  private pubKey: PubKey;
  private privKey: Buffer;

  /**
   *
   * @param privKey
   */
  constructor(privKey: Buffer) {
    this.pubKey = new PubKeySecp256k1(secp256k1.pointFromScalar(privKey)!);
    this.privKey = privKey;
  }

  /**
   *
   */
  getPubKey() {
    return this.pubKey;
  }

  /**
   *
   * @param message
   */
  sign(message: string): Buffer {
    const hash = crypto
      .createHash("sha256")
      .update(message)
      .digest("hex");
    const buffer = Buffer.from(hash, "hex");
    const signature = secp256k1.sign(buffer, this.privKey);

    return signature;
  }

  /**
   *
   */
  toBuffer() {
    return new Buffer(this.privKey);
  }

  /**
   *
   */
  toBase64() {
    return this.privKey.toString("base64");
  }

  /**
   * JSON.stringify
   */
  toJSON() {
    return this.toBase64();
  }

  /**
   *
   * @param value
   */
  static fromBase64(value: string) {
    const buffer = new Buffer(value, "base64");
    return new this(buffer);
  }
}
