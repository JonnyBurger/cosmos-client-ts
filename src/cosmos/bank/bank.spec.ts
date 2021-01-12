import { CosmosSDK, AccAddress } from "../..";
import { auth } from "../auth";
import { bank } from ".";
import { PrivKeySecp256k1 } from "../crypto";

test("bank", async () => {
  const sdk = new CosmosSDK("", "test");

  // get account info
  const privKeyBuffer = Buffer.from(
    "36d1043c6e23eb15c928da41043bfd183b6ce13f9e592c9a45ac431c4a08b924",
    "hex",
  );
  const privKey = new PrivKeySecp256k1(privKeyBuffer);
  const fromAddress = AccAddress.fromPublicKey(privKey.getPubKey());
  const account = await auth
    .accountsAddressGet(sdk, fromAddress)
    .then((res) => res.data.result);

  // get unsigned tx
  const toAddress = fromAddress;

  const unsignedStdTx = await bank
    .accountsAddressTransfersPost(sdk, toAddress, {
      base_req: {
        from: fromAddress.toBech32(),
        memo: "Hello, world!",
        chain_id: sdk.chainID,
        account_number: account.account_number.toString(),
        sequence: account.sequence.toString(),
        gas: "",
        gas_adjustment: "",
        fees: [],
        simulate: false,
      },
      amount: [{ denom: "token", amount: "1000" }],
    })
    .then((res) => res.data);

  // sign
  const signedStdTx = auth.signStdTx(
    sdk,
    privKey,
    unsignedStdTx,
    account.account_number.toString(),
    account.sequence.toString(),
  );

  // broadcast
  const result = await auth
    .txsPost(sdk, signedStdTx, "sync")
    .then((res) => res.data);

  console.log(result);
});
