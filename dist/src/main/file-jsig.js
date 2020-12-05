"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.FileJsig = void 0;
var did_jwt_1 = require("did-jwt");
var exceptions_1 = require("./exceptions");
var model_1 = require("./model");
var adm_zip_1 = __importDefault(require("adm-zip"));
var Util = __importStar(require("util"));
var Crypto = __importStar(require("crypto"));
var JWT = __importStar(require("jsonwebtoken"));
var SIG_FILE = "signature.jsig";
var FILE_UPDATE_NAME_REGEX = new RegExp(/^(?<name>.*)(?<ver>\(sig-update-(?<verNumber>\d)\))(?<extension>.*)$/);
var FileJsig = /** @class */ (function () {
    function FileJsig() {
    }
    FileJsig.signFile = function (buffer, filename, signer, signOptions, metadata, digestAlgorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var checksum, payload, jwt, signatures, zip;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        checksum = Crypto.createHash(digestAlgorithm || "sha256")
                            .update(buffer)
                            .digest("hex")
                            .toString();
                        payload = metadata || {};
                        payload["file"] = filename;
                        payload["file_checksum"] = checksum;
                        payload["digest_algorithm"] = digestAlgorithm || "sha256";
                        return [4 /*yield*/, signer.sign(payload, signOptions)];
                    case 1:
                        jwt = _a.sent();
                        signatures = new model_1.JSigJWTs();
                        signatures.addSignature(jwt);
                        zip = new adm_zip_1.default();
                        zip.addFile(filename, buffer);
                        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
                        return [2 /*return*/, zip.toBuffer()];
                }
            });
        });
    };
    FileJsig.witness = function (jsigFile, signer, signOptions, metadata, digestAlgorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var zip, sigFileEntry, signatures, jwts, prevJwtDecoded, filename, fileEntry, file, checksum, payload, witnessJwt;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        zip = new adm_zip_1.default(jsigFile);
                        sigFileEntry = zip.getEntry(SIG_FILE);
                        if (!sigFileEntry)
                            throw new exceptions_1.VerificationException("Signature file not found!");
                        signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
                        jwts = signatures.getSignatures();
                        // 2) Check if there are any signatures
                        if (jwts.size == 0)
                            throw new exceptions_1.VerificationException("No signatures found!");
                        prevJwtDecoded = JWT.decode(jwts.get(jwts.size - 1));
                        filename = prevJwtDecoded["file"];
                        fileEntry = zip.getEntry(filename);
                        if (!fileEntry)
                            throw new exceptions_1.VerificationException("Subject file not found!");
                        file = fileEntry.getData();
                        checksum = Crypto.createHash(digestAlgorithm || "sha256")
                            .update(file)
                            .digest("hex")
                            .toString();
                        payload = metadata || {};
                        payload["file"] = filename;
                        payload["file_checksum"] = checksum;
                        payload["prev_sig_hash"] = signatures.getLastSigHash();
                        payload["digest_algorithm"] = digestAlgorithm || "sha256";
                        return [4 /*yield*/, signer.sign(payload, signOptions)];
                    case 1:
                        witnessJwt = _a.sent();
                        // 6) Add the signature
                        signatures.addSignature(witnessJwt);
                        // 7) Updtate the zip file
                        zip.deleteFile(SIG_FILE);
                        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
                        return [2 /*return*/, zip.toBuffer()];
                }
            });
        });
    };
    FileJsig.witnessWithFileUpdate = function (jsigFile, updatedFile, signer, signOptions, metadata, digestAlgorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var zip, sigFileEntry, signatures, jwts, checksum, prevJwtDecoded, filename, updatedFilename, filnameHasVersion, filenameElements, i, matcher, groups, prevVersionNumber, newVersion, payload, witnessJwt;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        zip = new adm_zip_1.default(jsigFile);
                        sigFileEntry = zip.getEntry(SIG_FILE);
                        if (!sigFileEntry)
                            throw new exceptions_1.VerificationException("Signature file not found!");
                        signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
                        jwts = signatures.getSignatures();
                        // 2) Check if there are any signatures
                        if (jwts.size == 0)
                            throw new exceptions_1.VerificationException("No signatures found!");
                        checksum = Crypto.createHash(digestAlgorithm || "sha256")
                            .update(updatedFile)
                            .digest("hex")
                            .toString();
                        prevJwtDecoded = JWT.decode(jwts.get(jwts.size - 1));
                        filename = prevJwtDecoded["file"];
                        filnameHasVersion = FILE_UPDATE_NAME_REGEX.test(filename);
                        if (!filnameHasVersion) {
                            filenameElements = filename.split(".");
                            updatedFilename = Util.format("%s(sig-update-%d)", filenameElements[0], 1);
                            // 4) Add the file extensions
                            for (i = 1; i < filenameElements.length; i++) {
                                updatedFilename += "." + filenameElements[i];
                            }
                        }
                        else {
                            matcher = FILE_UPDATE_NAME_REGEX.exec(filename);
                            groups = matcher.groups;
                            prevVersionNumber = groups["verNumber"];
                            newVersion = Util.format("(sig-update-%d)", Number(prevVersionNumber) + 1);
                            updatedFilename = Util.format("%s%s%s", groups["name"], newVersion, groups["extension"]);
                        }
                        payload = metadata || {};
                        payload["file"] = updatedFilename;
                        payload["file_checksum"] = checksum;
                        payload["prev_sig_hash"] = signatures.getLastSigHash();
                        payload["digest_algorithm"] = digestAlgorithm || "sha256";
                        return [4 /*yield*/, signer.sign(payload, signOptions)];
                    case 1:
                        witnessJwt = _a.sent();
                        // 6) Add the signature
                        signatures.addSignature(witnessJwt);
                        // 7) Update the zip
                        zip.addFile(updatedFilename, updatedFile);
                        zip.deleteFile(SIG_FILE);
                        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
                        return [2 /*return*/, zip.toBuffer()];
                }
            });
        });
    };
    FileJsig.addSignatureToFile = function (jsigFile, signature) {
        var zip = new adm_zip_1.default(jsigFile);
        // 1) Get the jwts
        var sigFileEntry = zip.getEntry(SIG_FILE);
        if (!sigFileEntry)
            throw new exceptions_1.JsigFileFormatException("Signature file not found!");
        // 2) Add the signature
        var signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
        signatures.addSignature(signature);
        // 3) Updtate the zip file
        zip.deleteFile(SIG_FILE);
        zip.addFile(SIG_FILE, Buffer.from(signatures.toJson()));
        return zip.toBuffer();
    };
    FileJsig.verify = function (resolver, buffer) {
        return __awaiter(this, void 0, void 0, function () {
            var zip, sigFileEntry, signatures, jwts, jwtIndexes, sigs, jwtIndexKeys, index, jwtIndex, jwt, decodedJwt, filename, fileEntry, file, digestAlgorithm, fileChecksum, verificationResult, verifiedPayload, prevJwt, prevHash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        zip = new adm_zip_1.default(buffer);
                        sigFileEntry = zip.getEntry(SIG_FILE);
                        if (!sigFileEntry)
                            throw new exceptions_1.VerificationException("Signature file not found!");
                        signatures = model_1.JSigJWTs.fromJson(sigFileEntry.getData().toString());
                        jwts = signatures.getSignatures();
                        jwtIndexes = Array.from(jwts.keys());
                        // 2) Check if there are any signatures
                        if (jwts.size == 0)
                            throw new exceptions_1.VerificationException("No signatures found!");
                        sigs = new Map();
                        jwtIndexKeys = Array.from(jwts.keys());
                        index = 0;
                        _a.label = 1;
                    case 1:
                        if (!(index < jwtIndexKeys.length)) return [3 /*break*/, 4];
                        jwtIndex = jwtIndexes[index];
                        jwt = jwts.get(jwtIndex);
                        decodedJwt = JWT.decode(jwt);
                        filename = decodedJwt["file"];
                        fileEntry = zip.getEntry(filename);
                        if (!fileEntry)
                            throw new exceptions_1.VerificationException("Subject file not found!");
                        file = fileEntry.getData();
                        digestAlgorithm = decodedJwt["digest_algorithm"];
                        fileChecksum = Crypto.createHash(digestAlgorithm || "sha256")
                            .update(file)
                            .digest("hex")
                            .toString();
                        return [4 /*yield*/, did_jwt_1.DIDJwt.verify(resolver, jwt)];
                    case 2:
                        verificationResult = _a.sent();
                        verifiedPayload = verificationResult.payload;
                        // 3) Verify the checksum
                        if (fileChecksum != verifiedPayload["file_checksum"])
                            throw new exceptions_1.VerificationException("The file checksum found in the" + " signature is incorrect!");
                        // 4) Verify the prev hash
                        // Get the prev hash
                        if (jwtIndex != 0) {
                            prevJwt = jwts.get(jwtIndex - 1);
                            prevHash = Crypto.createHash("sha256")
                                .update(Buffer.from(prevJwt))
                                .digest("hex")
                                .toString();
                            if (prevHash != verifiedPayload["prev_sig_hash"])
                                throw new exceptions_1.VerificationException("The previous signature hash " +
                                    "found in the signature is incorrect!");
                        }
                        sigs.set(jwtIndex, verificationResult);
                        _a.label = 3;
                    case 3:
                        index++;
                        return [3 /*break*/, 1];
                    case 4: return [2 /*return*/, { signatures: sigs }];
                }
            });
        });
    };
    return FileJsig;
}());
exports.FileJsig = FileJsig;
