import { JwtSigner } from "../jwt-signer";
import { JWK } from "node-jose";
import JWT from "jsonwebtoken";
export declare class NodeJoseJwtSigner implements JwtSigner {
    private signer;
    constructor(key: JWK.Key, options?: JWT.SignOptions);
    sign(payload: object): string;
}
