import { assert } from "chai"
import { FileJsig, JwtSigner, NodeJoseJwtSigner } from "../";
import { DidJwk, getResolver } from "node-did-jwk";
import { Resolver } from "did-resolver";
import { JWK } from "node-jose";

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

    const jwk1: JWK.Key = await JWK.createKey("EC", "P-256", { alg: "ES256" });
    const jwk2: JWK.Key = await JWK.createKey("EC", "P-256", { alg: "ES256" });


    did1 = new DidJwk(jwk1);
    did2 = new DidJwk(jwk2);

    jwtSigner1 = new NodeJoseJwtSigner(jwk1, {
      issuer: did1.getDidUri(),
      algorithm: "ES256",
      keyid: "keys-1"
    });
    jwtSigner2 = new NodeJoseJwtSigner(jwk2, {
      issuer: did2.getDidUri(),
      algorithm: "ES256",
      keyid: "keys-1"
    });
  });

  it("It should sign a file", () => {
    let data: Buffer = fs.readFileSync(path.join(__dirname, "test.pdf"));

    signedFile1 = FileJsig.signFile(data, "test.pdf",
      jwtSigner1, { name: "This is the name of the issuer" });

    assert.isNotNull("");
  });

  it("File signature should be valid", () => {
    assert.doesNotThrow(async () => {
      await FileJsig.verify(resolver, signedFile1);
    });
  });

  it("Should witness the signed file", () => {
    assert.doesNotThrow(() => {
      witnessedFile1 = FileJsig.witness(signedFile1, jwtSigner2);

      fs.writeFileSync(path.join(__dirname, "signed.zip"), witnessedFile1);
    });
  })

  it("Witnessed file signature should be valid", () => {
    assert.doesNotThrow(async () => {
      await FileJsig.verify(resolver, witnessedFile1);
    });
  });

  it("Witness file signature with updated file", () => {
    assert.doesNotThrow(() => {

      const updatedFile: Buffer =
        fs.readFileSync(path.join(__dirname, "test-modified.pdf"));

      witnessedFile2 = FileJsig.witnessWithFileUpdate(witnessedFile1, updatedFile,
        jwtSigner2);

      fs.writeFileSync(path.join(__dirname, "signed2.zip"), witnessedFile2);
    });
  });

  it("Witnessed file signature with updated file should be valid", () => {
    assert.doesNotThrow(async () => {
      await FileJsig.verify(resolver, witnessedFile2);
    });
  });

  it("Witness file signature with second updated file", () => {
    assert.doesNotThrow(() => {

      const updatedFile: Buffer =
        fs.readFileSync(path.join(__dirname, "test-modified-1.pdf"));

      witnessedFile3 = FileJsig.witnessWithFileUpdate(witnessedFile2, updatedFile,
        jwtSigner2);

      fs.writeFileSync(path.join(__dirname, "signed3.zip"), witnessedFile3);
    });
  });

  it("Witnessed file signature with the second updated file should be valid", () => {
    assert.doesNotThrow(async () => {
      await FileJsig.verify(resolver, witnessedFile3);
    });
  });


});
