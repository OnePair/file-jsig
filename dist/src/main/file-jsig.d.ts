/// <reference types="node" />
import { JwtSigner } from "did-jwt";
import { Resolver } from "did-resolver";
import JWT from "jsonwebtoken";
export declare class FileJsig {
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner): Buffer;
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner, signOptions?: JWT.SignOptions): Buffer;
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner, signOptions?: JWT.SignOptions, metadata?: object): Buffer;
    static witness(jsigFile: Buffer, signer: JwtSigner): Buffer;
    static witness(jsigFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions): Buffer;
    static witness(jsigFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions, metadata?: object): Buffer;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner): Buffer;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions): Buffer;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions, metadata?: object): Buffer;
    static verify(resolver: Resolver, buffer: Buffer): Promise<object>;
}
