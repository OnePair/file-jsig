import { JwtSigner } from "../jwt-signer";
import { JWK } from "node-jose";
import JWT from "jsonwebtoken";
export declare class NodeJwtSigner implements JwtSigner {
    private key;
    private options;
    constructor(key: JWK.Key, options?: JWT.SignOptions);
    sign(payload: object): string;
}
