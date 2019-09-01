import * as bech32 from "bech32";
import { Address, bech32Prefix } from "./address";

/**
 * ValAddress
 */
export class ValAddress extends Address {
  /**
   * Bech32フォーマットのアドレスに変換する。
   */
  public toBech32() {
    const words = bech32.toWords(Buffer.from(this._value));
    return bech32.encode(bech32Prefix.valAddr, words);
  }

  /**
   *
   * @param valAddress
   */
  public static fromBech32(valAddress: string) {
    const { prefix, words } = bech32.decode(valAddress);
    if (prefix !== bech32Prefix.valAddr) {
      throw Error();
    }

    return new ValAddress(bech32.fromWords(words));
  }

  /**
   * JSON.stringify
   */
  public toJSON() {
    return this.toBech32();
  }
}
