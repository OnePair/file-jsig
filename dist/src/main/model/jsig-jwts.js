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
Object.defineProperty(exports, "__esModule", { value: true });
exports.JSigJWTs = void 0;
var Crypto = __importStar(require("crypto"));
var JSIG_FILE_VERSION_V_ONE_BETA = "0.0.1-beta";
var JSigJWTs = /** @class */ (function () {
    function JSigJWTs(signatures) {
        this.signatures = signatures || new Map();
    }
    JSigJWTs.prototype.getSignatures = function () {
        return this.signatures;
    };
    JSigJWTs.prototype.getLastSigHash = function () {
        var sigIndexs = Array.from(this.signatures.keys());
        if (sigIndexs.length == 0)
            return null;
        var lastSigIndex = Math.max.apply(Math, sigIndexs);
        var lastJwt = this.signatures.get(lastSigIndex);
        var sigHash = Crypto.createHash("sha256")
            .update(Buffer.from(lastJwt))
            .digest("hex").toString();
        return sigHash;
    };
    JSigJWTs.prototype.addSignature = function (signature) {
        var sigIndexs = Array.from(this.signatures.keys());
        if (sigIndexs.length == 0)
            this.signatures.set(0, signature);
        else {
            this.signatures.set(Math.max.apply(Math, sigIndexs) + 1, signature);
        }
    };
    JSigJWTs.prototype.toJson = function () {
        var jsigJson = {};
        this.signatures.forEach(function (value, key) {
            jsigJson[key] = value;
        });
        jsigJson["version"] = JSIG_FILE_VERSION_V_ONE_BETA;
        return JSON.stringify(jsigJson);
    };
    JSigJWTs.fromJson = function (jsonStr) {
        var jsigJson = JSON.parse(jsonStr);
        var signatures = new Map();
        var keysNum = Object.keys(jsigJson).length;
        var jwtIndex = 0;
        while (jwtIndex in jsigJson &&
            jwtIndex <= keysNum) {
            if (jwtIndex in jsigJson)
                signatures.set(jwtIndex, jsigJson[jwtIndex]);
            jwtIndex += 1;
        }
        return new JSigJWTs(signatures);
    };
    return JSigJWTs;
}());
exports.JSigJWTs = JSigJWTs;
