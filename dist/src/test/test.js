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
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
var util_1 = __importDefault(require("util"));
var chai_1 = require("chai");
var did_resolver_1 = require("did-resolver");
var did_jwt_1 = require("did-jwt");
var node_jose_1 = require("node-jose");
var __1 = require("..");
var node_did_jwk_1 = require("node-did-jwk");
var DID = "did:jwk:ZUp3bGprMFRRa0FBUVAvTG5qT2pRdWxXYklPeWtSajIwb2dkSDV2S1JxVHB2N2VtMjN1SE4vTStnRFp2c0FKUUF4TkFpNVRqMW5tZUJuTW9MbkZvek5YYTdoNkNhVW1RVmdMRFNacFZibzdrdzY1OXZvakptL2lhamJrM2t4VnVDWHR4YzRTLzlad1hscTl2WWxoak5ZZ3o1VHduV05aOUtkb1BmVXVPVkd5Tk12QWhXZTZWeE9YRnVIS0VVVC9OdmJkMnZ6WGx1dWd5VWNJV1EyR0ZYTjBtMmpVOHNTSHhVRmRTRzN4LzNydzdoQT09";
var JWK_1 = {
    kty: "EC",
    kid: "FPsTzIzibaXH39qMwp-IJ4Ekm-rZcdgmQhN5OKusveI",
    alg: "ES256",
    crv: "P-256",
    x: "7JUDBaEqZ9Vag6_3eZ5DU4YLzxueRk0uHjVUEe8L6cQ",
    y: "REYx1hSyContjAiwg04ZJrNXmNQDMeClXTrzcSNwjkM",
    d: "KVqyXXDtmSYaakBvHgDWZyubxG8V4x5KCdlBoyhek3c",
};
describe("FILE jsig tests", function () { return __awaiter(void 0, void 0, void 0, function () {
    var resolver;
    return __generator(this, function (_a) {
        before(function () { return __awaiter(void 0, void 0, void 0, function () {
            var jwkResolver;
            return __generator(this, function (_a) {
                jwkResolver = node_did_jwk_1.getResolver();
                resolver = new did_resolver_1.Resolver({
                    jwk: jwkResolver,
                });
                return [2 /*return*/];
            });
        }); });
        it("Should sign file", function () { return __awaiter(void 0, void 0, void 0, function () {
            var data, jwk, signer, signedFile;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        data = fs_1.default.readFileSync(path_1.default.join(__dirname, "resources/test.pdf"));
                        return [4 /*yield*/, node_jose_1.JWK.asKey(JWK_1)];
                    case 1:
                        jwk = _a.sent();
                        signer = new did_jwt_1.NodeJwtSigner(jwk);
                        return [4 /*yield*/, __1.FileJsig.signFile(data, "test.pdf", signer, {
                                //issuer: DID,
                                algorithm: "ES256",
                                keyid: util_1.default.format("%s#keys-1", DID),
                            }, { name: "This is the name of the issuer" })];
                    case 2:
                        signedFile = _a.sent();
                        chai_1.assert.isNotNull(signedFile);
                        return [2 /*return*/];
                }
            });
        }); });
        it("File signature verification should pass", function () { return __awaiter(void 0, void 0, void 0, function () {
            var file;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        file = fs_1.default.readFileSync(path_1.default.join(__dirname, "./resources/signed_pdf.zip"));
                        return [4 /*yield*/, __1.FileJsig.verify(resolver, file)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        }); });
        return [2 /*return*/];
    });
}); });
