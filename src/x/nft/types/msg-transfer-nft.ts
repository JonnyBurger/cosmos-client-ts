import { Amino } from "../../../tendermint/amino";
import { AccAddress } from "../../../types/cosmos-sdk/address/acc-address";

@Amino.RegisterConcrete('cosmos-sdk/MsgTransferNFT')
export class MsgTransferNFT {
  constructor(
    public Sender: AccAddress,
    public Recipient: AccAddress,
    public Denom: string,
    public ID: string
  ) {

  }

  /**
   * @see Amino.reviver
   * @param obj 
   */
  public static fromJSON(obj: any) {
    return new this(
      AccAddress.fromBech32(obj.Sender),
      AccAddress.fromBech32(obj.Recipient),
      obj.Denom,
      obj.ID
    );
  }
}