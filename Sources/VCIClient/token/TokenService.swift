import Foundation

class TokenService {
    let networkManager: NetworkManager
    init(networkManager: NetworkManager? = nil) {
        self.networkManager = networkManager ?? NetworkManager.shared
    }

    func getAccessToken(
        getTokenResponse: @escaping TokenResponseCallback,
        tokenEndpoint: String,
        timeoutMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        preAuthCode: String,
        txCode: String? = nil,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> TokenResponse {
        return try await obtainAccessToken(
            grantType: .preAuthorized,
            getTokenResponse: getTokenResponse,
            tokenEndpoint: tokenEndpoint,
            timeoutMillis: timeoutMillis,
            preAuthCode: preAuthCode,
            txCode: txCode,
            dpopManager: dpopManager
        )
    }

    func getAccessToken(
        getTokenResponse: @escaping TokenResponseCallback,
        tokenEndpoint: String,
        timeoutMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        authCode: String,
        clientId: String? = nil,
        redirectUri: String? = nil,
        codeVerifier: String? = nil,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> TokenResponse {
        return try await obtainAccessToken(
            grantType: .authorizationCode,
            getTokenResponse: getTokenResponse,
            tokenEndpoint: tokenEndpoint,
            timeoutMillis: timeoutMillis,
            authCode: authCode,
            clientId: clientId,
            redirectUri: redirectUri,
            codeVerifier: codeVerifier,
            dpopManager: dpopManager
        )
    }

    private func obtainAccessToken(
        grantType: GrantType,
        getTokenResponse: @escaping TokenResponseCallback,
        tokenEndpoint: String,
        timeoutMillis: Int64,
        preAuthCode: String? = nil,
        txCode: String? = nil,
        authCode: String? = nil,
        clientId: String? = nil,
        redirectUri: String? = nil,
        codeVerifier: String? = nil,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> TokenResponse {
        let dpopProof = dpopManager.isInitialized ? try dpopManager.generateTokenProof() : nil
        let tokenRequest = TokenRequest(
            grantType: grantType,
            tokenEndpoint: tokenEndpoint,
            authCode: authCode,
            preAuthCode: preAuthCode,
            txCode: txCode,
            clientId: clientId,
            redirectUri: redirectUri,
            codeVerifier: codeVerifier,
            dpopProof: dpopProof
        )

        return try await getTokenResponse(tokenRequest)
    }
}
