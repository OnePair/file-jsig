import Crypto from "crypto";

export class JSigJWTs {
  private signatures: Map<number, string>;

  constructor(signatures?: Map<number, string>) {
    this.signatures = signatures || new Map<number, string>();
  }

  public getSignatures(): Map<number, string> {
    return this.signatures;
  }

  public getLastSigHash(): string {
    let sigIndexs: number[] = Array.from(this.signatures.keys());

    if (sigIndexs.length == 0)
      return null;
    let lastSigIndex: number = Math.max(...sigIndexs);
    let lastJwt: string = this.signatures.get(lastSigIndex);

    let sigHash: string = Crypto.createHash("sha256")
      .update(Buffer.from(lastJwt))
      .digest("hex").toString();

    return sigHash;
  }

  public addSignature(signature: string): void {
    let sigIndexs: number[] = Array.from(this.signatures.keys());
    if (sigIndexs.length == 0)
      this.signatures.set(0, signature);
    else {
      this.signatures.set(Math.max(...sigIndexs) + 1, signature);
    }
  }

  public toJson(): string {
    let jsigJson: object = {};

    this.signatures.forEach((value: string, key: number) => {
      jsigJson[key] = value;
    });

    return JSON.stringify(jsigJson);
  }

  public static fromJson(jsonStr: string): JSigJWTs {
    let jsigJson: object = JSON.parse(jsonStr);
    let signatures: Map<number, string> = new Map<number, string>();

    let keysNum: number = Object.keys(jsigJson).length;
    let jwtIndex: number = 0;

    while (jwtIndex in jsigJson &&
      jwtIndex <= keysNum) {

      if (jwtIndex in jsigJson)
        signatures.set(jwtIndex, jsigJson[jwtIndex]);

      jwtIndex += 1;
    }

    return new JSigJWTs(signatures);
  }
}
