"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var did_jwt_1 = require("did-jwt");
var exceptions_1 = require("./exceptions");
var model_1 = require("./model");
var util_1 = __importDefault(require("util"));
var adm_zip_1 = __importDefault(require("adm-zip"));
var crypto_1 = __importDefault(require("crypto"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var SIG_FILE = "signature.jsig";
var FILE_UPDATE_NAME_REGEX = new RegExp(/^(?<name>.*)(?<ver>\(sig-update-(?<verNumber>\d)\))(?<extension>.*)$/);
var FileJsig = /** @class */ (function () {
    function FileJsig() {
    }
    FileJsig.signFile = function (buffer, filename, signer, metadata, digestAlgorithm) {
        // 1) Generate the checksum
        var checksum = crypto_1.default.createHash(digestAlgorithm || "sha256")
            .update(buffer)
            .digest("hex").toString();
        var payload = metadata || {};
        payload["file"] = filename;
        payload["file_checksum"] = checksum;
        payload["digest_algorithm"] = digestAlgorithm || "sha256";
        // 2) Create the JWT
        //const jwt: string = DIDJwt.sign(payload, jwk, options);
        var jwt = signer.sign(payload);
        var signatures = new model_1.JSigJWTs();
        signatures.addSignature(jwt);
        // 3) Assemble the files in a zip file. File extension should be .<extension>.jsig
        var zip = new adm_zip_1.default();
        zip.addFile(filename, buffer);
        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
        return zip.toBuffer();
    };
    FileJsig.witness = function (jsigFile, signer, metadata, digestAlgorithm) {
        var zip = new adm_zip_1.default(jsigFile);
        // 1) Get the jwts
        var sigFileEntry = zip.getEntry(SIG_FILE);
        if (!sigFileEntry)
            throw new exceptions_1.VerificationException("Signature file not found!");
        var signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
        var jwts = signatures.getSignatures();
        // 2) Check if there are any signatures
        if (jwts.size == 0)
            throw new exceptions_1.VerificationException("No signatures found!");
        // 3) Get the file
        // Get the previous one
        var prevJwtDecoded = jsonwebtoken_1.default.decode(jwts.get(jwts.size - 1));
        var filename = prevJwtDecoded["file"];
        var fileEntry = zip.getEntry(filename);
        if (!fileEntry)
            throw new exceptions_1.VerificationException("Subject file not found!");
        var file = fileEntry.getData();
        // 4) Generate the file checksum
        var checksum = crypto_1.default.createHash(digestAlgorithm || "sha256")
            .update(file)
            .digest("hex").toString();
        // 5) Create the jwt
        var payload = metadata || {};
        payload["file"] = filename;
        payload["file_checksum"] = checksum;
        payload["prev_sig_hash"] = signatures.getLastSigHash();
        payload["digest_algorithm"] = digestAlgorithm || "sha256";
        //const witnessJwt: string = DIDJwt.sign(payload, jwk, options);
        var witnessJwt = signer.sign(payload);
        // 6) Add the signature
        signatures.addSignature(witnessJwt);
        // 7) Updtate the zip file
        zip.deleteFile(SIG_FILE);
        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
        return zip.toBuffer();
    };
    FileJsig.witnessWithFileUpdate = function (jsigFile, updatedFile, signer, metadata, digestAlgorithm) {
        var zip = new adm_zip_1.default(jsigFile);
        // 1) Get the jwts
        var sigFileEntry = zip.getEntry(SIG_FILE);
        if (!sigFileEntry)
            throw new exceptions_1.VerificationException("Signature file not found!");
        var signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
        var jwts = signatures.getSignatures();
        // 2) Check if there are any signatures
        if (jwts.size == 0)
            throw new exceptions_1.VerificationException("No signatures found!");
        // 3) Generate checksum from the updated file
        var checksum = crypto_1.default.createHash(digestAlgorithm || "sha256")
            .update(updatedFile)
            .digest("hex").toString();
        // 3) Create file name with version update
        var prevJwtDecoded = jsonwebtoken_1.default.decode(jwts.get(jwts.size - 1));
        var filename = prevJwtDecoded["file"];
        var updatedFilename;
        // Check whether the filename has a version in it
        var filnameHasVersion = FILE_UPDATE_NAME_REGEX.test(filename);
        if (!filnameHasVersion) {
            var filenameElements = filename.split(".");
            updatedFilename = util_1.default.format("%s(sig-update-%d)", filenameElements[0], 1);
            // 4) Add the file extensions
            for (var i = 1; i < filenameElements.length; i++) {
                updatedFilename += "." + filenameElements[i];
            }
        }
        else {
            var matcher = FILE_UPDATE_NAME_REGEX.exec(filename);
            var groups = matcher.groups;
            var prevVersionNumber = groups["verNumber"];
            var newVersion = util_1.default.format("(sig-update-%d)", Number(prevVersionNumber) + 1);
            updatedFilename = util_1.default.format("%s%s%s", groups["name"], newVersion, groups["extension"]);
        }
        // 5) Create the jwt
        var payload = metadata || {};
        payload["file"] = updatedFilename;
        payload["file_checksum"] = checksum;
        payload["prev_sig_hash"] = signatures.getLastSigHash();
        payload["digest_algorithm"] = digestAlgorithm || "sha256";
        var witnessJwt = signer.sign(payload);
        // 6) Add the signature
        signatures.addSignature(witnessJwt);
        // 7) Update the zip
        zip.addFile(updatedFilename, updatedFile);
        zip.deleteFile(SIG_FILE);
        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
        return zip.toBuffer();
    };
    FileJsig.verify = function (resolver, buffer) {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
                        var zip_1, sigFileEntry, signatures, jwts_1, jwtIndexes_1, sigs_1;
                        var _this = this;
                        return __generator(this, function (_a) {
                            try {
                                zip_1 = new adm_zip_1.default(buffer);
                                sigFileEntry = zip_1.getEntry(SIG_FILE);
                                if (!sigFileEntry)
                                    throw new exceptions_1.VerificationException("Signature file not found!");
                                signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
                                jwts_1 = signatures.getSignatures();
                                jwtIndexes_1 = Array.from(jwts_1.keys());
                                // 2) Check if there are any signatures
                                if (jwts_1.size == 0)
                                    throw new exceptions_1.VerificationException("No signatures found!");
                                sigs_1 = new Map();
                                //const sigs: object = {};
                                // Verify the signatures
                                jwtIndexes_1.forEach(function (jwtIndex) { return __awaiter(_this, void 0, void 0, function () {
                                    var jwt, decodedJwt, issuerDID, filename, fileEntry, file, digestAlgorithm, fileChecksum, verifiedDecodedJwt, prevJwt, prevHash;
                                    return __generator(this, function (_a) {
                                        switch (_a.label) {
                                            case 0:
                                                jwt = jwts_1.get(jwtIndex);
                                                decodedJwt = jsonwebtoken_1.default.decode(jwt);
                                                issuerDID = decodedJwt["iss"];
                                                filename = decodedJwt["file"];
                                                fileEntry = zip_1.getEntry(filename);
                                                if (!fileEntry)
                                                    throw new exceptions_1.VerificationException("Subject file not found!");
                                                file = fileEntry.getData();
                                                digestAlgorithm = decodedJwt["digest_algorithm"];
                                                fileChecksum = crypto_1.default.createHash(digestAlgorithm || "sha256")
                                                    .update(file)
                                                    .digest("hex").toString();
                                                return [4 /*yield*/, did_jwt_1.DIDJwt.verify(resolver, jwt, issuerDID)];
                                            case 1:
                                                verifiedDecodedJwt = _a.sent();
                                                // 3) Verify the checksum
                                                if (fileChecksum != verifiedDecodedJwt["file_checksum"])
                                                    throw new exceptions_1.VerificationException("The file checksum found in the" +
                                                        " signature is incorrect!");
                                                // 4) Verify the prev hash
                                                // Get the prev hash
                                                if (jwtIndex != 0) {
                                                    prevJwt = jwts_1.get(jwtIndex - 1);
                                                    prevHash = crypto_1.default.createHash("sha256")
                                                        .update(Buffer.from(prevJwt))
                                                        .digest("hex").toString();
                                                    if (prevHash != verifiedDecodedJwt["prev_sig_hash"])
                                                        throw new exceptions_1.VerificationException("The previous signature hash " +
                                                            "found in the signature is incorrect!");
                                                }
                                                sigs_1.set(jwtIndex, verifiedDecodedJwt["iss"]);
                                                if ((jwtIndex + 1) == jwtIndexes_1.length) {
                                                    onSuccess({ "signatures": sigs_1 });
                                                }
                                                return [2 /*return*/];
                                        }
                                    });
                                }); });
                            }
                            catch (err) {
                                onError(err);
                            }
                            return [2 /*return*/];
                        });
                    }); })];
            });
        });
    };
    return FileJsig;
}());
exports.FileJsig = FileJsig;
