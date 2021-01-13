import * as bech32 from "bech32";
import { PubKey } from "../../crypto";
import { Address, bech32Prefix } from "./address";

/**
 * ValAddress
 */
export class ValAddress extends Address {
  /**
   *
   */
  toString() {
    const words = bech32.toWords(Buffer.from(this._value));
    return bech32.encode(bech32Prefix.valAddr, words);
  }

  /**
   * For `JSON.stringify`
   */
  toJSON() {
    return this.toString();
  }

  /**
   *
   * @param valAddress
   */
  static fromString(valAddress: string) {
    const { prefix, words } = bech32.decode(valAddress);

    return new ValAddress(bech32.fromWords(words));
  }

  static fromPublicKey(pubKey: PubKey) {
    return new ValAddress(pubKey.address());
  }
}
