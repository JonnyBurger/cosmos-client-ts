import * as bech32 from 'bech32';
import * as crypto from 'crypto';

const prefix = {
  main: 'cosmos',
  account: 'acc',
  validator: 'val',
  consensus: 'cons',
  public: 'pub',
  operator: 'oper',
  address: 'addr'
};
const bech32Prefix = {
  accAddr: prefix.main,
  accPub: prefix.main + prefix.public,
  valAddr: prefix.main + prefix.validator + prefix.operator,
  valPub: prefix.main + prefix.validator + prefix.operator + prefix.public,
  consAddr: prefix.main + prefix.validator + prefix.consensus,
  consPub: prefix.main + prefix.validator + prefix.consensus + prefix.public
};

export class Address extends Uint8Array {
  constructor(value: Uint8Array) {
    const addressLength = 20;
    if (value.length !== addressLength) {
      throw Error();
    }
    super(value);
  }

  private static hash160(buffer: Buffer): Buffer {
    const sha256Hash: Buffer = crypto.createHash('sha256')
      .update(buffer)
      .digest();
    try {
      return crypto.createHash('rmd160')
        .update(sha256Hash)
        .digest();
    } catch (err) {
      return crypto.createHash('ripemd160')
        .update(sha256Hash)
        .digest();
    }
  }

  public static fromPublicKey(publicKey: Buffer) {
    return new Address(this.hash160(publicKey));
  }
}

export class AccAddress extends Address {
  public toBech32() {
    const words = bech32.toWords(Buffer.from(this));
    return bech32.encode(bech32Prefix.accAddr, words);
  }

  public static fromBech32(accAddress: string) {
    const { prefix, words } = bech32.decode(accAddress)
    if (prefix !== bech32Prefix.accAddr) {
      throw Error();
    }

    return new AccAddress(bech32.fromWords(words));
  }
}
