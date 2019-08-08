import { StdTx } from "../../auth/types/stdtx";
import { result } from "./result";

export interface TxQuery {
    hash: string;
    height: number;
    tx: StdTx;
    result: result;
}