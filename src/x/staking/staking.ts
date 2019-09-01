import { CosmosSDK } from "../..";
import { StdTx } from "../auth/types/std-tx";
import { DelegateRequest } from "./types/delegate-request";
import { UndelegateRequest } from "./types/undelegate-request";
import { RedelegateRequest } from "./types/redelegate-request";
import { AccAddress } from "../../types/cosmos-sdk/address/acc-address";
import { ValAddress } from "../../types/cosmos-sdk/address/val-address";
import { QueryDelegatorParams } from "./types/query-delegator-params";
import { QueryValidatorParams } from "./types/query-validator-params";
import { QueryBondsParams } from "./types/query-bonds-params";
import { QueryRedelegationParams } from "./types/query-redelegation-params";
import { TxsQueryType } from "./types/txs-query-params";
import { Delegation } from "./types/delegation";
import { UnboundingDelegation } from "./types/unbounding-delegation";
import { TxQuery } from "./types/tx-query";
import { Validator } from "./types/validator";
import { Redelegation } from "./types/redelegation";
import { Pool } from "./types/pool";
import { Parameters } from "./types/parameters";
import { MsgDelegate } from "./types/msg-delegate";
import { MsgBeginRedelegate } from "./types/msg-begin-redelegate";
import { MsgUndelegate } from "./types/msg-undelegate";

/**
 *
 */
export module Staking {
  /**
   *
   * /staking/delegators/${delegatorAddress}/delegations
   * @param delegatorAddr
   * @param delegateRequest
   */
  export function postDelegation(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    delegateRequest: DelegateRequest
  ) {
    return host.post<StdTx>(
      `/staking/delegators/${delegatorAddr.toBech32()}/delegations`,
      delegateRequest
    );
  }

  /**
   * /staking/delegators/${delegatorAddress}/unbonding_delegations
   * @param host
   * @param delegatorAddr
   * @param undelegateRequest
   */
  export function postUnbondingDelegation(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    undelegateRequest: UndelegateRequest
  ) {
    return host.post<StdTx>(
      `/staking/delegators/${delegatorAddr.toBech32()}/unbonding_delegations`,
      undelegateRequest
    );
  }

  /**
   * staking/delegators/${delegatorAddress}/redelegations
   * @param host
   * @param delegatorAddr
   * @param redelegateRequest
   */
  export function postRedelegation(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    redelegateRequest: RedelegateRequest
  ) {
    return host.post<StdTx>(
      `/staking/delegators/${delegatorAddr.toBech32()}/redelegations`,
      redelegateRequest
    );
  }

  export function getDelegatorDelegations(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    queryDelegatorParams: QueryDelegatorParams
  ) {
    return host.get<Delegation>(
      `/staking/delegators/${delegatorAddr.toBech32()}/delegations`,
      queryDelegatorParams
    );
  }

  export function getDelegatorUnbondingDelegations(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    queryValidatorParams: QueryValidatorParams
  ) {
    return host.get<UnboundingDelegation>(
      `/staking/delegators/${delegatorAddr.toBech32()}/unbonding_delegations`,
      queryValidatorParams
    );
  }

  export function getDelegatorTxs(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    txsQueryType: TxsQueryType
  ) {
    let types = "";
    if (txsQueryType.bond) {
      types += "bond ;";
    }
    if (txsQueryType.unbond) {
      types += "unbond ;";
    }
    if (txsQueryType.redelegate) {
      types += "redelegate ;";
    }
    return host.get<TxQuery>(
      `/staking/delegators/${delegatorAddr.toBech32()}/txs`,
      { types }
    );
  }

  export function getDelegatorValidators(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    queryDelegatorParams: QueryDelegatorParams
  ) {
    return host.get<Validator>(
      `/staking/delegators/${delegatorAddr.toBech32()}/validators`,
      queryDelegatorParams
    );
  }

  export function getDelegatorValidator(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    validatorAddr: ValAddress,
    queryBondsParams: QueryBondsParams
  ) {
    return host.get<Validator>(
      `/staking/delegators/${delegatorAddr}/validators/${validatorAddr}`,
      queryBondsParams
    );
  }

  export function getDelegation(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    validatorAddr: ValAddress,
    queryBondsParams: QueryBondsParams
  ) {
    return host.get<Delegation>(
      `/staking/delegators/${delegatorAddr}/delegations/${validatorAddr}`,
      queryBondsParams
    );
  }

  export function getUnbondingDelegation(
    host: CosmosSDK,
    delegatorAddr: AccAddress,
    validatorAddr: ValAddress,
    queryBondsParams: QueryBondsParams
  ) {
    return host.get<UnboundingDelegation>(
      `/staking/delegators/${delegatorAddr.toBech32()}/unbonding_delegations/${validatorAddr.toBech32()}`,
      queryBondsParams
    );
  }

  export function getRedelegations(
    host: CosmosSDK,
    queryRedelegationParams: QueryRedelegationParams
  ) {
    return host.get<Redelegation>(
      `/staking/redelegations`,
      queryRedelegationParams
    );
  }

  export function getValidators(
    host: CosmosSDK,
    queryValidatorParams: QueryValidatorParams
  ) {
    return host.get<Validator>(`/staking/validators`, queryValidatorParams);
  }

  export function getValidator(
    host: CosmosSDK,
    validatorAddr: ValAddress,
    queryValidatorParams: QueryValidatorParams
  ) {
    return host.get<Validator>(
      `/staking/validators/${validatorAddr.toBech32()}`,
      queryValidatorParams
    );
  }

  export function getValidatorDelegations(
    host: CosmosSDK,
    validatorAddr: ValAddress,
    queryValidatorParams: QueryValidatorParams
  ) {
    return host.get<Delegation>(
      `/staking/validators/${validatorAddr.toBech32()}/delegations`,
      queryValidatorParams
    );
  }

  export function getValidatorUnbondingDelegations(
    host: CosmosSDK,
    validatorAddr: ValAddress,
    queryValidatorParams: QueryValidatorParams
  ) {
    return host.get<UnboundingDelegation>(
      `/staking/validators/${validatorAddr.toBech32()}/unbonding_delegations`,
      queryValidatorParams
    );
  }

  export function getPool(host: CosmosSDK) {
    return host.get<Pool>(`/staking/pool`);
  }

  export function getParameters(host: CosmosSDK) {
    return host.get<Parameters>(`/staking/parameters`);
  }
}
