import * as crypto from "crypto";
import { PrivKeyEd25519 } from ".";
import { AccAddress } from "../../types";

test("ed25519", () => {
  const bytes = crypto.randomBytes(32);
  const key = new PrivKeyEd25519(bytes);
  const address = AccAddress.fromPublicKey(key.pubKey());
  const str = address.toBech32();

  console.log(bytes.toString("hex"));
  console.log(str);
});
