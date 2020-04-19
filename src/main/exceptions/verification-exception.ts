export class VerificationException extends Error {
  constructor(message) {
      super(message); // (1)
      this.name = "VerificationException"; // (2)
    }
}
