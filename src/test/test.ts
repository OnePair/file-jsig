import fs from "fs";
import path from "path";
import util from "util";

import { assert } from "chai";

import { Resolver } from "did-resolver";
import { JwtSigner, NodeJwtSigner } from "did-jwt";
import { JWK } from "node-jose";
import { FileJsig } from "..";
import { getResolver } from "node-did-jwk";

const DID =
  "did:jwk:ZUp3bGprMFRRa0FBUVAvTG5qT2pRdWxXYklPeWtSajIwb2dkSDV2S1JxVHB2N2VtMjN1SE4vTStnRFp2c0FKUUF4TkFpNVRqMW5tZUJuTW9MbkZvek5YYTdoNkNhVW1RVmdMRFNacFZibzdrdzY1OXZvakptL2lhamJrM2t4VnVDWHR4YzRTLzlad1hscTl2WWxoak5ZZ3o1VHduV05aOUtkb1BmVXVPVkd5Tk12QWhXZTZWeE9YRnVIS0VVVC9OdmJkMnZ6WGx1dWd5VWNJV1EyR0ZYTjBtMmpVOHNTSHhVRmRTRzN4LzNydzdoQT09";

const JWK_1 = {
  kty: "EC",
  kid: "FPsTzIzibaXH39qMwp-IJ4Ekm-rZcdgmQhN5OKusveI",
  alg: "ES256",
  crv: "P-256",
  x: "7JUDBaEqZ9Vag6_3eZ5DU4YLzxueRk0uHjVUEe8L6cQ",
  y: "REYx1hSyContjAiwg04ZJrNXmNQDMeClXTrzcSNwjkM",
  d: "KVqyXXDtmSYaakBvHgDWZyubxG8V4x5KCdlBoyhek3c",
};

describe("FILE jsig tests", async () => {
  let resolver: Resolver;

  before(async () => {
    const jwkResolver = getResolver();
    resolver = new Resolver({
      jwk: jwkResolver,
    });
  });

  it("Should sign file", async () => {
    const data: Buffer = fs.readFileSync(
      path.join(__dirname, "resources/test.pdf")
    );

    const jwk = await JWK.asKey(JWK_1);

    const signer: JwtSigner = new NodeJwtSigner(jwk);

    const signedFile: Buffer = await FileJsig.signFile(
      data,
      "test.pdf",
      signer,
      {
        //issuer: DID,
        algorithm: "ES256",
        keyid: util.format("%s#keys-1", DID),
      },
      { name: "This is the name of the issuer" }
    );

    assert.isNotNull(signedFile);
  });

  it("File signature verification should pass", async () => {
    const file: Buffer = fs.readFileSync(
      path.join(__dirname, "./resources/signed_pdf.zip")
    );

    await FileJsig.verify(resolver, file);
  });
});
