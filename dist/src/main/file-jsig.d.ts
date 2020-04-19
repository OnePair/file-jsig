/// <reference types="node" />
import { Resolver } from "did-resolver";
import { JwtSigner } from "./signers";
export declare class FileJsig {
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner): Buffer;
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner): Buffer;
    static signFile(buffer: Buffer, filename: string, signer: JwtSigner, metadata?: object): Buffer;
    static witness(jsigFile: Buffer, signer: JwtSigner): Buffer;
    static witness(jsigFile: Buffer, signer: JwtSigner): Buffer;
    static witness(jsigFile: Buffer, signer: JwtSigner, metadata?: object): Buffer;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner): Buffer;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner): Buffer;
    static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer, signer: JwtSigner, metadata?: object): Buffer;
    static verify(resolver: Resolver, buffer: Buffer): Promise<object>;
}
