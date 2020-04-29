export declare class JSigJWTs {
    private signatures;
    constructor(signatures?: Map<number, string>);
    getSignatures(): Map<number, string>;
    getLastSigHash(): string;
    addSignature(signature: string): void;
    toJson(): string;
    static fromJson(jsonStr: string): JSigJWTs;
}
