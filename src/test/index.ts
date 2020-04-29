import { expect, assert } from "chai";
import { FileJsig } from "../";
import { DidJwk, getResolver } from "node-did-jwk";
import { Resolver } from "did-resolver";
import { JWK } from "node-jose";
import { NodeJwtSigner, JwtSigner } from "did-jwt";

import fs from "fs";
import path from "path";


describe("File JSIG tests", () => {

  let jwtSigner1: JwtSigner;
  let jwtSigner2: JwtSigner;

  let did1: DidJwk;
  let did2: DidJwk;

  let resolver: Resolver;

  let signedFile1: Buffer;
  let witnessedFile1: Buffer;
  let witnessedFile2: Buffer;
  let witnessedFile3: Buffer;

  before(async () => {
    const jwkResolver = getResolver();
    resolver = new Resolver({
      jwk: jwkResolver
    });

    const jwk1: JWK.Key = await JWK.asKey(fs.readFileSync(path.join(__dirname,
      "resources/keys/jwk1.json")));
    const jwk2: JWK.Key = await JWK.asKey(fs.readFileSync(path.join(__dirname,
      "resources/keys/jwk2.json")));

    did1 = new DidJwk(jwk1);
    did2 = new DidJwk(jwk2);

    jwtSigner1 = new NodeJwtSigner(jwk1);

    jwtSigner2 = new NodeJwtSigner(jwk2);
  });

  it("It should sign a file without an exception", () => {
    let data: Buffer = fs.readFileSync(path.join(__dirname, "resources/test.pdf"));

    signedFile1 = FileJsig.signFile(data, "test.pdf",
      jwtSigner1, {
        issuer: did1.getDidUri(),
        algorithm: "ES256",
        keyid: "keys-1"
      }, { name: "This is the name of the issuer" });

    expect(signedFile1).to.be.a("Uint8Array");
  });

  it("File signature should be valid", async () => {
    const results = await FileJsig.verify(resolver, signedFile1);

    expect(results).to.be.a("object");
  });

  it("Should witness the signed file without throwing an exception", async () => {
    witnessedFile1 = FileJsig.witness(signedFile1, jwtSigner2, {
      issuer: did2.getDidUri(),
      algorithm: "ES256",
      keyid: "keys-1"
    });

    fs.writeFileSync(path.join(__dirname, "resources/output/signed.zip"), witnessedFile1);

    expect(witnessedFile1).to.be.a("Uint8Array");
  })

  it("Witnessed file signature should be valid", async () => {
    const results = await FileJsig.verify(resolver, witnessedFile1);

    expect(results).to.be.a("object");
  });

  it("Witness file signature with updated file without throwing an exception", () => {
    const updatedFile: Buffer =
      fs.readFileSync(path.join(__dirname, "resources/test-modified.pdf"));

    witnessedFile2 = FileJsig.witnessWithFileUpdate(witnessedFile1, updatedFile,
      jwtSigner2, {
        issuer: did2.getDidUri(),
        algorithm: "ES256",
        keyid: "keys-1"
      });

    fs.writeFileSync(path.join(__dirname, "resources/output/signed2.zip"), witnessedFile2);

    expect(witnessedFile2).to.be.a("Uint8Array");
  });

  it("Witnessed file signature with updated file should be valid", async () => {
    const results = await FileJsig.verify(resolver, witnessedFile2);

    expect(results).to.be.a("object");
  });

  it("Witness file signature with second updated file without throwing an exception", () => {
    const updatedFile: Buffer =
      fs.readFileSync(path.join(__dirname, "resources/test-modified-1.pdf"));

    witnessedFile3 = FileJsig.witnessWithFileUpdate(witnessedFile2, updatedFile,
      jwtSigner2, {
        issuer: did2.getDidUri(),
        algorithm: "ES256",
        keyid: "keys-1"
      });

    fs.writeFileSync(path.join(__dirname, "resources/output/signed3.zip"), witnessedFile3);

    expect(witnessedFile3).to.be.a("Uint8Array");
  });

  it("Witnessed file signature with the second updated file should be valid", async () => {
    const results = await FileJsig.verify(resolver, witnessedFile3);
    expect(results).to.be.a("object");
  });

  it("File signed by wrong issuer should be invalid", async () => {
    const signedFile = fs.readFileSync(path.join(__dirname, "resources/signed_wrong_first_issuer.zip"))
    var error = null;

    try {
      await FileJsig.verify(resolver, signedFile);
    } catch (err) {
      error = err;
    }

    expect(error).to.not.be.a("null");
  });

  it("File witnessed by wrong issuer should be invalid", async () => {
    const signedFile = fs.readFileSync(path.join(__dirname, "resources/witnessed_wrong_issuer.zip"))
    var error = null;

    try {
      await FileJsig.verify(resolver, signedFile);
    } catch (err) {
      error = err;
    }

    expect(error).to.not.be.a("null");
  });

  it("File witnessed and updated by wrong issuer should be invalid", async () => {
    const signedFile = fs.readFileSync(path.join(__dirname, "resources/witnessed_with_update_wrong_issuer.zip"))
    var error = null;

    try {
      await FileJsig.verify(resolver, signedFile);
    } catch (err) {
      error = err;
    }

    expect(error).to.not.be.a("null");
  });
});
