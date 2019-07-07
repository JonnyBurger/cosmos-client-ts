import * as request from 'request';
import { StdSignDoc, StdFee } from '../x/auth/stdtx';
import { Msg } from '../cosmos-sdk/msg';

export class CosmosSdkHost {
  constructor(
    private url: string,
    private chainId: string
  ) {

  }

  public get<T>(path: string, params?: any): Promise<T> {
    return new Promise((resolve, reject) => {
      request.get(
        {
          uri: this.url + path,
          method: 'GET',
          json: true,
          qs: params
        },
        (error, response, body) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(body);
        }
      );
    });
  }

  public post<T>(path: string, params: any): Promise<T> {
    return new Promise((resolve, reject) => {
      request.post(
        {
          uri: this.url + path,
          method: 'POST',
          json: true,
          body: params
        },
        (error, response, body) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(body);
        }
      );
    });
  }

  public createStdSignDoc(
    accountNumber: bigint,
    fee: StdFee,
    memo: string,
    msgs: Msg[],
    sequence: string
  ): StdSignDoc {
    return {
      account_number: accountNumber,
      chain_id: this.chainId,
      fee: fee,
      memo: memo,
      msgs: msgs,
      sequence: sequence
    }
  }
}
