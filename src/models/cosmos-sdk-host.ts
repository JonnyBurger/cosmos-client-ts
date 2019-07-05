import * as request from 'request';

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
        (body) => {
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
        (body) => {
          resolve(body);
        }
      );
    });
  }
}
