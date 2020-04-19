import { JwtSigner } from "../jwt-signer";
import { JWK } from "node-jose";
import { DIDJwt, NodeJwtSigner } from "did-jwt";


import JWT from "jsonwebtoken";

export class NodeJoseJwtSigner implements JwtSigner {

  //private key: JWK.Key;
  //private options: JWT.SignOptions;
  private signer: NodeJwtSigner;

  constructor(key: JWK.Key, options?: JWT.SignOptions) {
    this.signer = new NodeJwtSigner(key, options);
    //this.key = key;
    //this.options = options || {};
  }

  sign(payload: object): string {
    return DIDJwt.sign(payload, this.signer);
  }
}
