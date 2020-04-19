"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var did_jwt_1 = require("did-jwt");
var NodeJwtSigner = /** @class */ (function () {
    function NodeJwtSigner(key, options) {
        this.key = key;
        this.options = options || {};
    }
    NodeJwtSigner.prototype.sign = function (payload) {
        return did_jwt_1.DIDJwt.sign(payload, this.key, this.options);
    };
    return NodeJwtSigner;
}());
exports.NodeJwtSigner = NodeJwtSigner;
