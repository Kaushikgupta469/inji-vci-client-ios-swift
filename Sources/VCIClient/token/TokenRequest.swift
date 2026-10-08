public struct TokenRequest {
    public let grantType: GrantType
    public let tokenEndpoint: String
    public let authCode: String?
    public let preAuthCode: String?
    public let txCode: String?
    public let clientId: String?
    public let redirectUri: String?
    public let codeVerifier: String?
    public let dpopProof: String?
}
