export interface JwtSigner {
    sign(payload: object): string;
}
