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
var chai_1 = require("chai");
var __1 = require("../");
var node_did_jwk_1 = require("node-did-jwk");
var did_resolver_1 = require("did-resolver");
var node_jose_1 = require("node-jose");
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
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
                    return [4 /*yield*/, node_jose_1.JWK.createKey("EC", "P-256", { alg: "ES256" })];
                case 1:
                    jwk1 = _a.sent();
                    return [4 /*yield*/, node_jose_1.JWK.createKey("EC", "P-256", { alg: "ES256" })];
                case 2:
                    jwk2 = _a.sent();
                    did1 = new node_did_jwk_1.DidJwk(jwk1);
                    did2 = new node_did_jwk_1.DidJwk(jwk2);
                    jwtSigner1 = new __1.NodeJoseJwtSigner(jwk1, {
                        issuer: did1.getDidUri(),
                        algorithm: "ES256",
                        keyid: "keys-1"
                    });
                    jwtSigner2 = new __1.NodeJoseJwtSigner(jwk2, {
                        issuer: did2.getDidUri(),
                        algorithm: "ES256",
                        keyid: "keys-1"
                    });
                    return [2 /*return*/];
            }
        });
    }); });
    it("It should sign a file", function () {
        var data = fs_1.default.readFileSync(path_1.default.join(__dirname, "test.pdf"));
        signedFile1 = __1.FileJsig.signFile(data, "test.pdf", jwtSigner1, { name: "This is the name of the issuer" });
        chai_1.assert.isNotNull("");
    });
    it("File signature should be valid", function () {
        chai_1.assert.doesNotThrow(function () { return __awaiter(void 0, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, signedFile1)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        }); });
    });
    it("Should witness the signed file", function () {
        chai_1.assert.doesNotThrow(function () {
            witnessedFile1 = __1.FileJsig.witness(signedFile1, jwtSigner2);
            fs_1.default.writeFileSync(path_1.default.join(__dirname, "signed.zip"), witnessedFile1);
        });
    });
    it("Witnessed file signature should be valid", function () {
        chai_1.assert.doesNotThrow(function () { return __awaiter(void 0, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, witnessedFile1)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        }); });
    });
    it("Witness file signature with updated file", function () {
        chai_1.assert.doesNotThrow(function () {
            var updatedFile = fs_1.default.readFileSync(path_1.default.join(__dirname, "test-modified.pdf"));
            witnessedFile2 = __1.FileJsig.witnessWithFileUpdate(witnessedFile1, updatedFile, jwtSigner2);
            fs_1.default.writeFileSync(path_1.default.join(__dirname, "signed2.zip"), witnessedFile2);
        });
    });
    it("Witnessed file signature with updated file should be valid", function () {
        chai_1.assert.doesNotThrow(function () { return __awaiter(void 0, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, witnessedFile2)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        }); });
    });
    it("Witness file signature with second updated file", function () {
        chai_1.assert.doesNotThrow(function () {
            var updatedFile = fs_1.default.readFileSync(path_1.default.join(__dirname, "test-modified-1.pdf"));
            witnessedFile3 = __1.FileJsig.witnessWithFileUpdate(witnessedFile2, updatedFile, jwtSigner2);
            fs_1.default.writeFileSync(path_1.default.join(__dirname, "signed3.zip"), witnessedFile3);
        });
    });
    it("Witnessed file signature with the second updated file should be valid", function () {
        chai_1.assert.doesNotThrow(function () { return __awaiter(void 0, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, __1.FileJsig.verify(resolver, witnessedFile3)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        }); });
    });
});
