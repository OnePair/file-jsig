import { VerificationResult } from "did-jwt";

export class JsigVerificationResult {
  signatures: Map<number, VerificationResult>;
}
