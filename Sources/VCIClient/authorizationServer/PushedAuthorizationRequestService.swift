import Foundation

class PushedAuthorizationRequestService {

    func pushAuthorizationRequest(
        parEndpoint: String,
        clientId: String,
        redirectUri: String,
        codeChallenge: String,
        state: String,
        nonce: String,
        scope: String? = nil,
        dpopJkt: String? = nil,
        codeChallengeMethod: CodeChallengeMethod = .s256,
        responseType: AuthorizationResponseType = .code,
        clientAuthParams: [String: String] = [:],
        timeoutMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        session: NetworkManager = NetworkManager.shared
    ) async throws -> PushedAuthorizationResponse {
        var params: [String: String] = [
            "response_type": responseType.rawValue,
            "client_id": clientId,
            "redirect_uri": redirectUri,
            "code_challenge": codeChallenge,
            "code_challenge_method": codeChallengeMethod.rawValue,
            "state": state,
            "nonce": nonce,
        ]

        if let scope = scope, !scope.isEmpty {
            params["scope"] = scope
        }

        if let dpopJkt = dpopJkt, !dpopJkt.isEmpty {
            params["dpop_jkt"] = dpopJkt
        }

        // Core authorization request params take precedence; clientAuthParams
        // (e.g. client_assertion) may only add keys, never override reserved fields.
        params.merge(clientAuthParams) { current, _ in current }

        let response: NetworkResponse
        do {
            response = try await session.sendRequest(
                url: parEndpoint,
                method: .post,
                headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue],
                bodyParams: params,
                timeoutMillis: timeoutMillis
            )
        } catch let e as VCIClientException {
            throw PushedAuthorizationRequestException(
                message: "PAR request failed at \(parEndpoint): \(e.message)",
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )
        } catch {
            throw PushedAuthorizationRequestException(
                message: "PAR request failed at \(parEndpoint): \(error.localizedDescription)",
                cause: error
            )
        }

        let parResponse: PushedAuthorizationResponse?
        do {
            parResponse = try JsonUtils.deserialize(
                response.body,
                as: PushedAuthorizationResponse.self
            )
        } catch {
            throw PushedAuthorizationRequestException(
                message: "Invalid PAR response from \(parEndpoint): \(error.localizedDescription)",
                cause: error
            )
        }

        guard let parResponse = parResponse, !parResponse.requestUri.isEmpty else {
            throw PushedAuthorizationRequestException(
                "Invalid PAR response from \(parEndpoint): missing request_uri"
            )
        }

        return parResponse
    }
}
