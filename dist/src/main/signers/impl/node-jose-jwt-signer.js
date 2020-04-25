"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var did_jwt_1 = require("did-jwt");
var NodeJoseJwtSigner = /** @class */ (function () {
    function NodeJoseJwtSigner(key, options) {
        this.signer = new did_jwt_1.NodeJwtSigner(key, options);
    }
    NodeJoseJwtSigner.prototype.sign = function (payload) {
        return did_jwt_1.DIDJwt.sign(payload, this.signer);
    };
    return NodeJoseJwtSigner;
}());
exports.NodeJoseJwtSigner = NodeJoseJwtSigner;
