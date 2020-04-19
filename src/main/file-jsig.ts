import { DIDJwt } from "did-jwt";
import { Resolver } from "did-resolver";
import { VerificationException } from "./exceptions";
import { JSigJWTs } from "./model";
import { JwtSigner } from "./signers";

import Util from "util";
import AdmZip from "adm-zip";
import Crypto from "crypto";
import JWT from "jsonwebtoken";

const SIG_FILE: string = "signature.jwts";

/*
* TODOs:
* 2) External signers
*/

export class FileJsig {

  public static signFile(buffer: Buffer, filename: string, signer: JwtSigner): Buffer
  public static signFile(buffer: Buffer, filename: string, signer: JwtSigner): Buffer
  public static signFile(buffer: Buffer, filename: string, signer: JwtSigner,
    metadata?: object): Buffer
  public static signFile(buffer: Buffer, filename: string, signer: JwtSigner,
    metadata?: object, digestAlgorithm?: string): Buffer {

    // 1) Generate the checksum
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(buffer)
      .digest("hex").toString();

    const payload: object = metadata || {};

    payload["file"] = filename;
    payload["file_checksum"] = checksum;
    payload["digest_algorithm"] = digestAlgorithm || "sha256";


    // 2) Create the JWT
    //const jwt: string = DIDJwt.sign(payload, jwk, options);
    const jwt: string = signer.sign(payload);

    const signatures: JSigJWTs = new JSigJWTs();
    signatures.addSignature(jwt);

    // 3) Assemble the files in a zip file. File extension should be .<extension>.jsig
    const zip: AdmZip = new AdmZip();
    zip.addFile(filename, buffer);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static witness(jsigFile: Buffer, signer: JwtSigner): Buffer;
  public static witness(jsigFile: Buffer, signer: JwtSigner): Buffer;
  public static witness(jsigFile: Buffer, signer: JwtSigner,
    metadata?: object): Buffer;
  public static witness(jsigFile: Buffer, signer: JwtSigner, metadata?: object,
    digestAlgorithm?: string): Buffer {
    const zip: AdmZip = new AdmZip(jsigFile);

    // 1) Get the jwts
    const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

    if (!sigFileEntry)
      throw new VerificationException("Signature file not found!");

    const signatures: JSigJWTs =
      JSigJWTs.fromJson(sigFileEntry.getData().toString());

    const jwts: Map<number, string> = signatures.getSignatures();

    // 2) Check if there are any signatures
    if (jwts.size == 0)
      throw new VerificationException("No signatures found!");

    // 3) Get the file

    // Get the previous one
    const prevJwtDecoded: any = JWT.decode(jwts.get(jwts.size - 1));
    const filename: string = prevJwtDecoded["file"];
    const fileEntry: AdmZip.IZipEntry = zip.getEntry(filename);

    if (!fileEntry)
      throw new VerificationException("Subject file not found!");

    const file: Buffer = fileEntry.getData();

    // 4) Generate the file checksum
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(file)
      .digest("hex").toString();

    // 5) Create the jwt
    const payload: object = metadata || {};

    payload["file"] = filename;
    payload["file_checksum"] = checksum;
    payload["prev_sig_hash"] = signatures.getLastSigHash();
    payload["digest_algorithm"] = digestAlgorithm || "sha256";

    //const witnessJwt: string = DIDJwt.sign(payload, jwk, options);
    const witnessJwt: string = signer.sign(payload);

    // 6) Add the signature
    signatures.addSignature(witnessJwt);

    // 7) Updtate the zip file
    zip.deleteFile(SIG_FILE);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer,
    signer: JwtSigner): Buffer;
  public static witnessWithFileUpdate(jsigFile: Buffer, updatedFile: Buffer,
    signer: JwtSigner): Buffer;
  public static witnessWithFileUpdate(jsigFile: Buffer,
    updatedFile: Buffer, signer: JwtSigner, metadata?: object): Buffer;
  public static witnessWithFileUpdate(jsigFile: Buffer,
    updatedFile: Buffer, signer: JwtSigner, metadata?: object,
    digestAlgorithm?: string): Buffer {

    const zip: AdmZip = new AdmZip(jsigFile);

    // 1) Get the jwts
    const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

    if (!sigFileEntry)
      throw new VerificationException("Signature file not found!");

    const signatures: JSigJWTs =
      JSigJWTs.fromJson(sigFileEntry.getData().toString());

    const jwts: Map<number, string> = signatures.getSignatures();

    // 2) Generate checksum from the updated file
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(updatedFile)
      .digest("hex").toString();

    // 3) Create file name with the new checksum
    const firstJwtDecoded: any = JWT.decode(jwts.get(0));
    const filename: string = firstJwtDecoded["file"];

    const filenameElements: Array<string> = filename.split(".");

    let updatedFilename: string = Util.format("%s-%s", filenameElements[0], checksum);

    // 4) Add the file extensions
    for (let i = 1; i < filenameElements.length; i++) {
      updatedFilename += "." + filenameElements[i];
    }

    // 5) Create the jwt
    const payload: object = metadata || {};

    payload["file"] = updatedFilename;
    payload["file_checksum"] = checksum;
    payload["prev_sig_hash"] = signatures.getLastSigHash();
    payload["digest_algorithm"] = digestAlgorithm || "sha256";

    const witnessJwt: string = signer.sign(payload);

    // 6) Add the signature
    signatures.addSignature(witnessJwt);

    // 7) Update the zip
    zip.addFile(updatedFilename, updatedFile);
    zip.deleteFile(SIG_FILE);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static async verify(resolver: Resolver, buffer: Buffer):
    Promise<object> {
    return new Promise<object>(async (onSuccess: Function, onError: Function) => {
      try {
        const zip: AdmZip = new AdmZip(buffer);

        // 1) Get the jwts
        const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

        if (!sigFileEntry)
          throw new VerificationException("Signature file not found!");

        const signatures: JSigJWTs =
          JSigJWTs.fromJson(sigFileEntry.getData().toString());
        const jwts: Map<number, string> = signatures.getSignatures();
        const jwtIndexes: Array<number> = Array.from(jwts.keys());

        // 2) Check if there are any signatures
        if (jwts.size == 0)
          throw new VerificationException("No signatures found!");

        const signers: Map<number, string> = new Map<number, string>();

        // Verify the signatures
        jwtIndexes.forEach(async (jwtIndex: number) => {
          const jwt: string = jwts.get(jwtIndex);
          const decodedJwt: any = JWT.decode(jwt);
          let issuerDID: string = decodedJwt["iss"];

          // 1) Generate the file checksum
          const filename: string = decodedJwt["file"];
          const fileEntry: AdmZip.IZipEntry = zip.getEntry(filename);

          if (!fileEntry)
            throw new VerificationException("Subject file not found!");

          const file: Buffer = fileEntry.getData();

          const digestAlgorithm: string = decodedJwt["digest_algorithm"];


          const fileChecksum: string = Crypto.createHash(digestAlgorithm || "sha256")
            .update(file)
            .digest("hex").toString();

          // 2) Verify the jwt
          const verifiedDecodedJwt: object =
            await DIDJwt.verify(resolver, jwt, issuerDID);

          // 3) Verify the checksum
          if (fileChecksum != verifiedDecodedJwt["file_checksum"])
            throw new VerificationException("The file checksum found in the" +
              " signature is incorrect!");

          // 4) Verify the prev hash

          // Get the prev hash
          if (jwtIndex != 0) {
            const prevJwt: string = jwts.get(jwtIndex - 1);

            const prevHash: string = Crypto.createHash("sha256")
              .update(Buffer.from(prevJwt))
              .digest("hex").toString();

            if (prevHash != verifiedDecodedJwt["prev_sig_hash"])
              throw new VerificationException("The previous signature hash " +
                "found in the signature is incorrect!");
          }

          signers.set(jwtIndex, verifiedDecodedJwt["iss"]);
        });

        onSuccess({ "signers": signers });
      } catch (err) {
        onError(err);
      }
    });
  }
}
