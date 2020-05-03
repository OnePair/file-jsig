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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var chai_1 = require("chai");
var __1 = require("../");
var node_did_jwk_1 = require("node-did-jwk");
var did_resolver_1 = require("did-resolver");
var node_jose_1 = require("node-jose");
var did_jwt_1 = require("did-jwt");
var fs = __importStar(require("fs"));
var path = __importStar(require("path"));
describe("File JSIG tests", function () {
    var jwtSigner1;
    var jwtSigner2;
    var did1;
    var did2;
    var resolver;
    var signedFile1;
    var witnessedFile1;
    var witnessedFile2;
    var witnessedFile3;
    before(function () { return __awaiter(void 0, void 0, void 0, function () {
        var jwkResolver, jwk1, jwk2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    jwkResolver = node_did_jwk_1.getResolver();
                    resolver = new did_resolver_1.Resolver({
                        jwk: jwkResolver
                    });
                    return [4 /*yield*/, node_jose_1.JWK.asKey(fs.readFileSync(path.join(__dirname, "resources/keys/jwk1.json")))];
                case 1:
                    jwk1 = _a.sent();
                    return [4 /*yield*/, node_jose_1.JWK.asKey(fs.readFileSync(path.join(__dirname, "resources/keys/jwk2.json")))];
                case 2:
                    jwk2 = _a.sent();
                    did1 = new node_did_jwk_1.DidJwk(jwk1);
                    did2 = new node_did_jwk_1.DidJwk(jwk2);
                    jwtSigner1 = new did_jwt_1.NodeJwtSigner(jwk1);
                    jwtSigner2 = new did_jwt_1.NodeJwtSigner(jwk2);
                    return [2 /*return*/];
            }
        });
    }); });
    it("It should sign a file without an exception", function () { return __awaiter(void 0, void 0, void 0, function () {
        var data;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    data = fs.readFileSync(path.join(__dirname, "resources/test.pdf"));
                    return [4 /*yield*/, __1.FileJsig.signFile(data, "test.pdf", jwtSigner1, {
                            issuer: did1.getDidUri(),
                            algorithm: "ES256",
                            keyid: "keys-1"
                        }, { name: "This is the name of the issuer" })];
                case 1:
                    signedFile1 = _a.sent();
                    chai_1.expect(signedFile1).to.be.a("Uint8Array");
                    return [2 /*return*/];
            }
        });
    }); });
    it("File signature should be valid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var results;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, signedFile1)];
                case 1:
                    results = _a.sent();
                    chai_1.expect(results).to.be.a("object");
                    return [2 /*return*/];
            }
        });
    }); });
    it("Should witness the signed file without throwing an exception", function () { return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, __1.FileJsig.witness(signedFile1, jwtSigner2, {
                        issuer: did2.getDidUri(),
                        algorithm: "ES256",
                        keyid: "keys-1"
                    })];
                case 1:
                    witnessedFile1 = _a.sent();
                    fs.writeFileSync(path.join(__dirname, "resources/output/signed.zip"), witnessedFile1);
                    chai_1.expect(witnessedFile1).to.be.a("Uint8Array");
                    return [2 /*return*/];
            }
        });
    }); });
    it("Witnessed file signature should be valid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var results;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, witnessedFile1)];
                case 1:
                    results = _a.sent();
                    chai_1.expect(results).to.be.a("object");
                    return [2 /*return*/];
            }
        });
    }); });
    it("Witness file signature with updated file without throwing an exception", function () { return __awaiter(void 0, void 0, void 0, function () {
        var updatedFile;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    updatedFile = fs.readFileSync(path.join(__dirname, "resources/test-modified.pdf"));
                    return [4 /*yield*/, __1.FileJsig.witnessWithFileUpdate(witnessedFile1, updatedFile, jwtSigner2, {
                            issuer: did2.getDidUri(),
                            algorithm: "ES256",
                            keyid: "keys-1"
                        })];
                case 1:
                    witnessedFile2 = _a.sent();
                    fs.writeFileSync(path.join(__dirname, "resources/output/signed2.zip"), witnessedFile2);
                    chai_1.expect(witnessedFile2).to.be.a("Uint8Array");
                    return [2 /*return*/];
            }
        });
    }); });
    it("Witnessed file signature with updated file should be valid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var results;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, witnessedFile2)];
                case 1:
                    results = _a.sent();
                    chai_1.expect(results).to.be.a("object");
                    return [2 /*return*/];
            }
        });
    }); });
    it("Witness file signature with second updated file without throwing an exception", function () { return __awaiter(void 0, void 0, void 0, function () {
        var updatedFile;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    updatedFile = fs.readFileSync(path.join(__dirname, "resources/test-modified-1.pdf"));
                    return [4 /*yield*/, __1.FileJsig.witnessWithFileUpdate(witnessedFile2, updatedFile, jwtSigner2, {
                            issuer: did2.getDidUri(),
                            algorithm: "ES256",
                            keyid: "keys-1"
                        })];
                case 1:
                    witnessedFile3 = _a.sent();
                    fs.writeFileSync(path.join(__dirname, "resources/output/signed3.zip"), witnessedFile3);
                    chai_1.expect(witnessedFile3).to.be.a("Uint8Array");
                    return [2 /*return*/];
            }
        });
    }); });
    it("Witnessed file signature with the second updated file should be valid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var results;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, witnessedFile3)];
                case 1:
                    results = _a.sent();
                    chai_1.expect(results).to.be.a("object");
                    return [2 /*return*/];
            }
        });
    }); });
    it("File signed by wrong issuer should be invalid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var signedFile, error, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    signedFile = fs.readFileSync(path.join(__dirname, "resources/signed_wrong_first_issuer.zip"));
                    error = null;
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, __1.FileJsig.verify(resolver, signedFile)];
                case 2:
                    _a.sent();
                    return [3 /*break*/, 4];
                case 3:
                    err_1 = _a.sent();
                    error = err_1;
                    return [3 /*break*/, 4];
                case 4:
                    chai_1.expect(error).to.not.be.a("null");
                    return [2 /*return*/];
            }
        });
    }); });
    it("File witnessed by wrong issuer should be invalid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var signedFile, error, err_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    signedFile = fs.readFileSync(path.join(__dirname, "resources/witnessed_wrong_issuer.zip"));
                    error = null;
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, __1.FileJsig.verify(resolver, signedFile)];
                case 2:
                    _a.sent();
                    return [3 /*break*/, 4];
                case 3:
                    err_2 = _a.sent();
                    error = err_2;
                    return [3 /*break*/, 4];
                case 4:
                    chai_1.expect(error).to.not.be.a("null");
                    return [2 /*return*/];
            }
        });
    }); });
    it("File witnessed and updated by wrong issuer should be invalid", function () { return __awaiter(void 0, void 0, void 0, function () {
        var signedFile, error, err_3;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    signedFile = fs.readFileSync(path.join(__dirname, "resources/witnessed_with_update_wrong_issuer.zip"));
                    error = null;
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, __1.FileJsig.verify(resolver, signedFile)];
                case 2:
                    _a.sent();
                    return [3 /*break*/, 4];
                case 3:
                    err_3 = _a.sent();
                    error = err_3;
                    return [3 /*break*/, 4];
                case 4:
                    chai_1.expect(error).to.not.be.a("null");
                    return [2 /*return*/];
            }
        });
    }); });
});
