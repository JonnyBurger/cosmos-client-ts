import { CosmosSDK } from "../..";
import { AccAddress } from "../../types/cosmos-sdk/address/acc-address";
import { SigningInfo } from "./types/signing-info";
import { SignParameter } from "./types/sign-parameter";
import { ValAddress } from "../../types/cosmos-sdk/address/val-address";
import { BaseReq } from "../../types/cosmos-sdk/rest";
import { StdTx } from "../auth/types/std-tx";

import { Amino } from "../../common/amino";
import { MsgUnjail } from "./types/msg-unjail";

export * from "./types";

export namespace Slashing {
  /**
   * Register codec
   */
  export function init() {
    Amino.RegisterConcrete('cosmos-sdk/MsgUnjail', MsgUnjail);
  }

  /**
   *
   */

  export function postUnjail(
    sdk: CosmosSDK,
    validatorAddr: ValAddress,
    baseReq: BaseReq
  ) {
    return sdk.post<StdTx>(
      `/slashing/validators/${validatorAddr}/unjail`,
      baseReq
    );
  }

  export function getParams(sdk: CosmosSDK, validatorPubKey: AccAddress) {
    return sdk.get<SigningInfo>(
      `/slashing/validators/${validatorPubKey}/signing_info`
    );
  }

  export function getSignInfo(sdk: CosmosSDK) {
    return sdk.get<SignParameter>("/slashing/signing_infos");
  }

  export function getSignInfos(sdk: CosmosSDK) {
    return sdk.get<SigningInfo>("/slashing/parameters");
  }
}

