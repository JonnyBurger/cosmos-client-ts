import { CosmosSdkHost } from "../../common/cosmos-sdk-host";
import { StdTx } from '../auth/types/stdtx';
import { DelegateRequest } from "./types/delegate-request";
import { UndelegateRequest } from "./types/undelegate-request";
import { RedelegateRequest } from "./types/redelegate-request";
import { AccAddress } from "../../types/cosmos-sdk/address/acc-address";
import { ValAddress } from "../../types/cosmos-sdk/address/val-address";
import { QueryDelegatorParams } from "./types/query-delegator-params";
import { QueryValidatorParams } from "./types/query-validator-params";

/**
 * Cosmos SDKにおけるx/stakingのRest APIをまとめたモジュール。
 */
export module Staking {
  /**
   * 
   * @param host /staking/delegators/${delegatorAddress}/delegations
   * @param delegatorAddr 
   * @param delegateRequest 
   */
  export function postDelegation(host: CosmosSdkHost, delegatorAddr: AccAddress, delegateRequest: DelegateRequest) {
    return host.post<StdTx>(`/staking/delegators/${delegatorAddr.toBech32()}/delegations`, delegateRequest);
  }

  /**
   * /staking/delegators/${delegatorAddress}/unbonding_delegations
   * @param host 
   * @param delegatorAddr 
   * @param undelegateRequest 
   */
  export function postUnbondingDelegation(host: CosmosSdkHost, delegatorAddr: AccAddress, undelegateRequest: UndelegateRequest) {
    return host.post<{}>(`/staking/delegators/${delegatorAddr.toBech32()}/unbonding_delegations`, undelegateRequest);
  }

  /**
   * staking/delegators/${delegatorAddress}/redelegations
   * @param host 
   * @param delegatorAddr 
   * @param redelegateRequest
   */
  export function postRedelegation(host: CosmosSdkHost, delegatorAddr: AccAddress, redelegateRequest: RedelegateRequest) {
    return host.post<StdTx>(`/staking/delegators/${delegatorAddr.toBech32()}/redelegations`, redelegateRequest);
  }

  export function getDelegatorDelegations(host: CosmosSdkHost, delegatorAddr: AccAddress, queryDelegatorParams: QueryDelegatorParams) {
    return host.get<DelegationResponses>(`/staking/delegators/${delegatorAddr.toBech32()}/delegations`, queryDelegatorParams);
  }

  export function getDelegatorUnbondingDelegations(host: CosmosSdkHost, delegatorAddr: AccAddress, queryValidatorParams: QueryValidatorParams) {
    return host.get<UnbondingDelegation[]>(`/staking/delegators/${delegatorAddr.toBech32()}/unbonding_delegations`, queryValidatorParams);
  }

  export function getDelegatorTxs(host: CosmosSdkHost, delegatorAddr: AccAddress) {
    return host.get<{}>(`/staking/delegators/${delegatorAddr.toBech32()}/txs`);
  }

  export function getDelegatorValidators(host: CosmosSdkHost, delegatorAddr: AccAddress) {
    return host.get<Validator[]>(`/staking/delegators/${delegatorAddr.toBech32()}/validators`);
  }

  export function getDelegatorValidator(host: CosmosSdkHost, delegatorAddr: AccAddress, validatorAddr: ValAddress) {
    return host.get<Validator>(`/staking/delegators/${delegatorAddr}/validators/${validatorAddr}`);
  }

  export function getDelegation(host: CosmosSdkHost, delegationAddr: AccAddress, validatorAddr: ValAddress) {
    return host.get<DelegationResponse>(`/staking/delegators/${delegationAddr}/delegations/${validatorAddr}`);
  }

  export function getUnbondingDelegation(host: CosmosSdkHost, delegatorAddr: AccAddress, validatorAddr: ValAddress) {
    return host.get<UnbondingDelegation>(`/staking/delegators/${delegatorAddr.toBech32()}/unbonding_delegations/${validatorAddr.toBech32()}`);
  }

  export function getRedelegations(host: CosmosSdkHost) {
    return host.get<RedelegationResponses>(`/staking/redelegations`);
  }

  export function getValidators(host: CosmosSdkHost) {
    return host.get<{}>(`/staking/validators`);
  }

  export function getValidator(host: CosmosSdkHost, validatorAddr: ValAddress) {
    return host.get<{}>(`/staking/validators/${validatorAddr.toBech32()}`);
  }

  export function getValidatorDelegations(host: CosmosSdkHost, validatorAddr: ValAddress) {
    return host.get<{}>(`/staking/validators/${validatorAddr.toBech32()}/delegations`);
  }

  export function getValidatorUnbondingDelegations(host: CosmosSdkHost, validatorAddr: ValAddress) {
    return host.get<{}>(`/staking/validators/${validatorAddr.toBech32()}/unbonding_delegations`);
  }

  export function getPool(host: CosmosSdkHost) {
    return host.get<ModuleCdc>(`/staking/pool`);
  }

  export function getParameters(host: CosmosSdkHost) {
    return host.get<ModuleCdc>(`/staking/parameters`);
  }
}