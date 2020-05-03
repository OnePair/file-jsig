/// <reference types="node" />
import { JwtSigner } from "did-jwt";
import { Resolver } from "did-resolver";
import * as JWT from "jsonwebtoken";
export declare class FileJsig {
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner): Promise<Buffer>;
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner, signOptions?: JWT.SignOptions): Promise<Buffer>;
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner, signOptions?: JWT.SignOptions, metadata?: object): Promise<Buffer>;
    static witness(jsigFile: Buffer, signer: JwtSigner): Promise<Buffer>;
    static witness(jsigFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions): Promise<Buffer>;
    static witness(jsigFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions, metadata?: object): Promise<Buffer>;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner): Promise<Buffer>;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions): Promise<Buffer>;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner, signOptions?: JWT.SignOptions, metadata?: object): Promise<Buffer>;
    static verify(resolver: Resolver, buffer: Buffer): Promise<object>;
}
