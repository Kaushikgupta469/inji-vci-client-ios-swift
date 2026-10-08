import Foundation

public struct Constants {
    public static let defaultNetworkTimeoutInMillis: Int64 = 10_000
    static let credentialIssuerWellknownUriSuffix: String = "/.well-known/openid-credential-issuer"
    
    static let MISSING_INTERACTION_TYPE_ERROR = "missing_interaction_type"

    static let authorizationHeader = "Authorization"
    static let dpopHeader = "DPoP"
    static let dpopNonceHeader = "DPoP-Nonce"
    static let wwwAuthenticateHeader = "WWW-Authenticate"

    static let dpopJwtType = "dpop+jwt"
    static let dpopTokenType = "DPoP"
    static let bearerTokenType = "Bearer"

    static let useDpopNonceError = "use_dpop_nonce"

    static let httpMethodPost = "POST"
    static let dpopProofLifetimeSeconds: TimeInterval = 60
}

