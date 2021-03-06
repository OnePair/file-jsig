import { DIDJwt, JwtSigner, VerificationResult } from "did-jwt";
import { Resolver } from "did-resolver";
import { VerificationException, JsigFileFormatException } from "./exceptions";
import { JSigJWTs, JsigVerificationResult } from "./model";

import AdmZip from "adm-zip";

import { pki } from "node-forge";

import * as Util from "util";
import * as Crypto from "crypto";
import * as JWT from "jsonwebtoken";

const SIG_FILE: string = "signature.jsig";

const FILE_UPDATE_NAME_REGEX: RegExp = new RegExp(
  /^(?<name>.*)(?<ver>\(sig-update-(?<verNumber>\d)\))(?<extension>.*)$/
);

export class FileJsig {
  public static async signFile(
    buffer: Buffer,
    filename: string,
    signer: JwtSigner
  ): Promise<Buffer>;
  public static async signFile(
    buffer: Buffer,
    filename: string,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions
  ): Promise<Buffer>;
  public static async signFile(
    buffer: Buffer,
    filename: string,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions,
    metadata?: object
  ): Promise<Buffer>;
  public static async signFile(
    buffer: Buffer,
    filename: string,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions,
    metadata?: object,
    digestAlgorithm?: string
  ): Promise<Buffer> {
    // 1) Generate the checksum
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(buffer)
      .digest("hex")
      .toString();

    const payload: object = metadata || {};

    payload["file"] = filename;
    payload["file_checksum"] = checksum;
    payload["digest_algorithm"] = digestAlgorithm || "sha256";

    // 2) Create the JWT
    //const jwt: string = DIDJwt.sign(payload, jwk, options);
    const jwt: string = await signer.sign(payload, signOptions);

    const signatures: JSigJWTs = new JSigJWTs();
    signatures.addSignature(jwt);

    // 3) Assemble the files in a zip file. File extension should be .<extension>.jsig
    const zip: AdmZip = new AdmZip();
    zip.addFile(filename, buffer);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static async witness(
    jsigFile: Buffer,
    signer: JwtSigner
  ): Promise<Buffer>;
  public static async witness(
    jsigFile: Buffer,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions
  ): Promise<Buffer>;
  public static witness(
    jsigFile: Buffer,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions,
    metadata?: object
  ): Promise<Buffer>;
  public static async witness(
    jsigFile: Buffer,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions,
    metadata?: object,
    digestAlgorithm?: string
  ): Promise<Buffer> {
    const zip: AdmZip = new AdmZip(jsigFile);

    // 1) Get the jwts
    const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

    if (!sigFileEntry)
      throw new VerificationException("Signature file not found!");

    const signatures: JSigJWTs = JSigJWTs.fromJson(
      sigFileEntry.getData().toString()
    );

    const jwts: Map<number, string> = signatures.getSignatures();

    // 2) Check if there are any signatures
    if (jwts.size == 0) throw new VerificationException("No signatures found!");

    // 3) Get the file

    // Get the previous one
    const prevJwtDecoded: any = JWT.decode(jwts.get(jwts.size - 1));
    const filename: string = prevJwtDecoded["file"];
    const fileEntry: AdmZip.IZipEntry = zip.getEntry(filename);

    if (!fileEntry) throw new VerificationException("Subject file not found!");

    const file: Buffer = fileEntry.getData();

    // 4) Generate the file checksum
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(file)
      .digest("hex")
      .toString();

    // 5) Create the jwt
    const payload: object = metadata || {};

    payload["file"] = filename;
    payload["file_checksum"] = checksum;
    payload["prev_sig_hash"] = signatures.getLastSigHash();
    payload["digest_algorithm"] = digestAlgorithm || "sha256";

    //const witnessJwt: string = DIDJwt.sign(payload, jwk, options);
    const witnessJwt: string = await signer.sign(payload, signOptions);

    // 6) Add the signature
    signatures.addSignature(witnessJwt);

    // 7) Updtate the zip file
    zip.deleteFile(SIG_FILE);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static async witnessWithFileUpdate(
    jsigFile: Buffer,
    updatedFile: Buffer,
    signer: JwtSigner
  ): Promise<Buffer>;
  public static async witnessWithFileUpdate(
    jsigFile: Buffer,
    updatedFile: Buffer,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions
  ): Promise<Buffer>;
  public static async witnessWithFileUpdate(
    jsigFile: Buffer,
    updatedFile: Buffer,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions,
    metadata?: object
  ): Promise<Buffer>;
  public static async witnessWithFileUpdate(
    jsigFile: Buffer,
    updatedFile: Buffer,
    signer: JwtSigner,
    signOptions?: JWT.SignOptions,
    metadata?: object,
    digestAlgorithm?: string
  ): Promise<Buffer> {
    const zip: AdmZip = new AdmZip(jsigFile);

    // 1) Get the jwts
    const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

    if (!sigFileEntry)
      throw new VerificationException("Signature file not found!");

    const signatures: JSigJWTs = JSigJWTs.fromJson(
      sigFileEntry.getData().toString()
    );

    const jwts: Map<number, string> = signatures.getSignatures();

    // 2) Check if there are any signatures
    if (jwts.size == 0) throw new VerificationException("No signatures found!");

    // 3) Generate checksum from the updated file
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(updatedFile)
      .digest("hex")
      .toString();

    // 3) Create file name with version update
    const prevJwtDecoded: any = JWT.decode(jwts.get(jwts.size - 1));
    const filename: string = prevJwtDecoded["file"];
    let updatedFilename: string;

    // Check whether the filename has a version in it
    const filnameHasVersion: boolean = FILE_UPDATE_NAME_REGEX.test(filename);

    if (!filnameHasVersion) {
      const filenameElements: Array<string> = filename.split(".");

      updatedFilename = Util.format(
        "%s(sig-update-%d)",
        filenameElements[0],
        1
      );

      // 4) Add the file extensions
      for (let i = 1; i < filenameElements.length; i++) {
        updatedFilename += "." + filenameElements[i];
      }
    } else {
      const matcher: RegExpExecArray = FILE_UPDATE_NAME_REGEX.exec(filename);
      const groups: object = matcher.groups;

      const prevVersionNumber: number = groups["verNumber"];
      const newVersion = Util.format(
        "(sig-update-%d)",
        Number(prevVersionNumber) + 1
      );

      updatedFilename = Util.format(
        "%s%s%s",
        groups["name"],
        newVersion,
        groups["extension"]
      );
    }

    // 5) Create the jwt
    const payload: object = metadata || {};

    payload["file"] = updatedFilename;
    payload["file_checksum"] = checksum;
    payload["prev_sig_hash"] = signatures.getLastSigHash();
    payload["digest_algorithm"] = digestAlgorithm || "sha256";

    const witnessJwt: string = await signer.sign(payload, signOptions);

    // 6) Add the signature
    signatures.addSignature(witnessJwt);

    // 7) Update the zip
    zip.addFile(updatedFilename, updatedFile);
    zip.deleteFile(SIG_FILE);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static addSignatureToFile(
    jsigFile: Buffer,
    signature: string
  ): Buffer {
    const zip: AdmZip = new AdmZip(jsigFile);

    // 1) Get the jwts
    const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

    if (!sigFileEntry)
      throw new JsigFileFormatException("Signature file not found!");

    // 2) Add the signature
    const signatures: JSigJWTs = JSigJWTs.fromJson(
      sigFileEntry.getData().toString()
    );

    signatures.addSignature(signature);

    // 3) Updtate the zip file
    zip.deleteFile(SIG_FILE);
    zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));

    return zip.toBuffer();
  }

  public static async verify(
    resolver: Resolver,
    buffer: Buffer
  ): Promise<JsigVerificationResult>;
  public static async verify(
    resolver: Resolver,
    buffer: Buffer,
    caStore?: pki.CAStore
  ): Promise<JsigVerificationResult> {
    const zip: AdmZip = new AdmZip(buffer);

    // 1) Get the jwts
    const sigFileEntry: AdmZip.IZipEntry = zip.getEntry(SIG_FILE);

    if (!sigFileEntry)
      throw new VerificationException("Signature file not found!");

    const signatures: JSigJWTs = JSigJWTs.fromJson(
      sigFileEntry.getData().toString()
    );
    const jwts: Map<number, string> = signatures.getSignatures();
    const jwtIndexes: Array<number> = Array.from(jwts.keys());

    // 2) Check if there are any signatures
    if (jwts.size == 0) throw new VerificationException("No signatures found!");

    const sigs: Map<number, VerificationResult> = new Map<
      number,
      VerificationResult
    >();
    //const sigs: object = {};

    // Verify the signatures
    const jwtIndexKeys: Array<number> = Array.from(jwts.keys());

    for (let index = 0; index < jwtIndexKeys.length; index++) {
      const jwtIndex: number = jwtIndexes[index];

      const jwt: string = jwts.get(jwtIndex);
      const decodedJwt: any = JWT.decode(jwt);
      //let issuerDID: string = decodedJwt["iss"];

      // 1) Generate the file checksum
      const filename: string = decodedJwt["file"];
      const fileEntry: AdmZip.IZipEntry = zip.getEntry(filename);

      if (!fileEntry)
        throw new VerificationException("Subject file not found!");

      const file: Buffer = fileEntry.getData();

      const digestAlgorithm: string = decodedJwt["digest_algorithm"];

      const fileChecksum: string = Crypto.createHash(
        digestAlgorithm || "sha256"
      )
        .update(file)
        .digest("hex")
        .toString();

      // 2) Verify the jwt
      const verificationResult: VerificationResult = await DIDJwt.verify(
        resolver,
        jwt,
        caStore
      );
      const verifiedPayload: object = verificationResult.payload;

      // 3) Verify the checksum
      if (fileChecksum != verifiedPayload["file_checksum"])
        throw new VerificationException(
          "The file checksum found in the" + " signature is incorrect!"
        );

      // 4) Verify the prev hash

      // Get the prev hash
      if (jwtIndex != 0) {
        const prevJwt: string = jwts.get(jwtIndex - 1);

        const prevHash: string = Crypto.createHash("sha256")
          .update(Buffer.from(prevJwt))
          .digest("hex")
          .toString();

        if (prevHash != verifiedPayload["prev_sig_hash"])
          throw new VerificationException(
            "The previous signature hash " +
              "found in the signature is incorrect!"
          );
      }
      sigs.set(jwtIndex, verificationResult);
    }
    return { signatures: sigs };
  }
}
