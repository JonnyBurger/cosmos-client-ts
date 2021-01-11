import { CosmosSDK } from "../../cosmos-sdk";
import { QueryApi } from "../../api";

export function params(sdk: CosmosSDK) {
  return new QueryApi(undefined, sdk.url).clientParams();
}
