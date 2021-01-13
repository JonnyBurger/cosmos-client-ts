import { QueryApi } from "../../generated/api";
import { CosmosClient } from "../../cosmos-sdk";

export function annualProvisions(sdk: CosmosClient) {
  return new QueryApi(undefined, sdk.url).annualProvisions();
}

export function inflation(sdk: CosmosClient) {
  return new QueryApi(undefined, sdk.url).inflation();
}

export function params(sdk: CosmosClient) {
  return new QueryApi(undefined, sdk.url).mintParams();
}
