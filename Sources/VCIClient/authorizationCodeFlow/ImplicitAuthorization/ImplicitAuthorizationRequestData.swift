import Foundation

struct ImplicitAuthorizationRequestData: AuthorizationRequestData {
    let authorizeUrl: String
    let clientMetadata: ClientMetadata
    let pkceSession: PKCESessionManager.PKCESession
    let scope: String
    let pushedAuthorizationRequestEndpoint: String?
    let requirePushedAuthorizationRequests: Bool?
    let dpopJkt: String

    init(
        authorizeUrl: String,
        clientMetadata: ClientMetadata,
        pkceSession: PKCESessionManager.PKCESession,
        scope: String,
        pushedAuthorizationRequestEndpoint: String? = nil,
        requirePushedAuthorizationRequests: Bool? = nil,
        dpopJkt: String
    ) {
        self.authorizeUrl = authorizeUrl
        self.clientMetadata = clientMetadata
        self.pkceSession = pkceSession
        self.scope = scope
        self.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint
        self.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests
        self.dpopJkt = dpopJkt
    }
}
