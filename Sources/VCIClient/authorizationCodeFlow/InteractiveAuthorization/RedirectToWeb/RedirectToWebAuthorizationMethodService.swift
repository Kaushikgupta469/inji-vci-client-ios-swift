final class RedirectToWebAuthorizationMethodService: AuthorizationMethodService {

    private let openWebPage: OpenWebPageCallback
    private let parService: PushedAuthorizationRequestService

    init(
        openWebPage: @escaping OpenWebPageCallback,
        parService: PushedAuthorizationRequestService = PushedAuthorizationRequestService()
    ) {
        self.openWebPage = openWebPage
        self.parService = parService
    }

    func type() -> String {
        return InteractionType.redirectToWeb.rawValue
    }

    func authorizeUser(
        requestData: AuthorizationRequestData
    ) async throws -> AuthorizationResponse {

        guard let request = requestData as? ImplicitAuthorizationRequestData else {
            throw InteractiveAuthorizationException(
                message: "RedirectToWebAuthorizationMethodService expects ImplicitAuthorizationRequestData but received \(Swift.type(of: requestData))"
            )
        }

        let parEndpoint = request.pushedAuthorizationRequestEndpoint
        let isParRequired = request.requirePushedAuthorizationRequests ?? false

        let authUrl: String
        if isParRequired {
            guard let parEndpoint, !parEndpoint.isEmpty else {
                throw PushedAuthorizationRequestException(
                    message: "Authorization server requires pushed authorization requests "
                        + "but did not advertise a pushed_authorization_request_endpoint"
                )
            }
            authUrl = try await buildAuthorizationUrlViaPushedRequest(
                request: request,
                parEndpoint: parEndpoint
            )
        } else if let parEndpoint, !parEndpoint.isEmpty {
            do {
                authUrl = try await buildAuthorizationUrlViaPushedRequest(
                    request: request,
                    parEndpoint: parEndpoint
                )
            } catch {
                Util.logWarning(
                    message: "PAR attempt failed at \(parEndpoint) and PAR is not required "
                        + "by the authorization server, falling back to the standard "
                        + "authorization request: \(error.localizedDescription)",
                    className: String(describing: Swift.type(of: self))
                )
                authUrl = buildStandardAuthorizationUrl(request: request)
            }
        } else {
            authUrl = buildStandardAuthorizationUrl(request: request)
        }

        let authorizationResponse = try await openWebPage(authUrl)

        if authorizationResponse["error"] != nil {
            return AuthorizationResponse(
                authorizationCode: nil,
                status: "error",
                error: authorizationResponse["error"] as? String,
                errorDescription: authorizationResponse["error_description"] as? String,
                authSession: nil
            )
        }

        guard let code = authorizationResponse["code"] as? String else {
            throw InteractiveAuthorizationException(
                message: "Missing code (authorization code) in successful redirect response"
            )
        }

        return AuthorizationResponse(
            authorizationCode: code,
            status: "success",
            error: nil,
            errorDescription: nil,
            authSession: authorizationResponse["auth_session"] as? String
        )
    }

    private func buildAuthorizationUrlViaPushedRequest(
        request: ImplicitAuthorizationRequestData,
        parEndpoint: String
    ) async throws -> String {
        let parResponse = try await parService.pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: request.clientMetadata.clientId,
            redirectUri: request.clientMetadata.redirectUri,
            codeChallenge: request.pkceSession.codeChallenge,
            state: request.pkceSession.state,
            nonce: request.pkceSession.nonce,
            scope: request.scope,
            dpopJkt: request.dpopJkt
        )
        return AuthorizationUrlBuilder.buildWithRequestUri(
            baseUrl: request.authorizeUrl,
            clientId: request.clientMetadata.clientId,
            requestUri: parResponse.requestUri
        )
    }

    private func buildStandardAuthorizationUrl(
        request: ImplicitAuthorizationRequestData
    ) -> String {
        return AuthorizationUrlBuilder.buildWithParameters(
            baseUrl: request.authorizeUrl,
            clientId: request.clientMetadata.clientId,
            redirectUri: request.clientMetadata.redirectUri,
            scope: request.scope,
            state: request.pkceSession.state,
            codeChallenge: request.pkceSession.codeChallenge,
            nonce: request.pkceSession.nonce,
            dpopJkt: request.dpopJkt
        )
    }
}

