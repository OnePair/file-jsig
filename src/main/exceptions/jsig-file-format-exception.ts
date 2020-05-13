

export class JsigFileFormatException extends Error {
  constructor(message) {
      super(message); // (1)
      this.name = "JsigFileFormatException"; // (2)
    }
}
