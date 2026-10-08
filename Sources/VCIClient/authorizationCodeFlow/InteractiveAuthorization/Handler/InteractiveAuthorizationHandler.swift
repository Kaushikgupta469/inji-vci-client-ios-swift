import Foundation

class InteractiveAuthorizationHandler {
    private let networkManager: NetworkManager
    
    init(networkManager: NetworkManager = NetworkManager.shared) {
        self.networkManager = networkManager
    }
    
    func handle(
        endpoint: String,
        clientMetadata: ClientMetadata,
        credentialConfigurationId: String,
        authorizationMethods: [AuthorizationMethod],
        pkceSession: PKCESessionManager.PKCESession,
        dpopJkt: String
    ) async throws -> AuthorizationResponse {
        
        do {
            let interactionTypesSupported = authorizationMethods.flatMap { method -> [String] in
                switch method {
                case .redirectToWeb:
                    return []

                case .presentationDuringIssuance:
                    return [
                        InteractionType.openId4VpPresentation.rawValue,
                        InteractionType.openId4VpPresentationIAE.rawValue
                    ]
                }
            }

            if interactionTypesSupported.isEmpty {
                throw InteractiveAuthorizationException(
                    message: "No supported interaction types found in authorization methods"
                )
            }
            
            let initialIarRequest = buildInitialIarRequest(
                clientMetadata: clientMetadata,
                credentialConfigurationId: credentialConfigurationId,
                pkce: pkceSession,
                interactionTypesSupported: interactionTypesSupported,
                dpopJkt: dpopJkt
            )
            
            let interactiveAuthorizationResponse = try await networkManager.sendRequest(
                url: endpoint,
                method: .post,
                headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue],
                bodyParams: initialIarRequest
            )
            
            let type: String = try extractTypeAndThrowIfError(interactiveAuthorizationResponse.body)
            
            if type == InteractionType.openId4VpPresentation.rawValue ||
               type == InteractionType.openId4VpPresentationIAE.rawValue {
                return try await handlePresentationInteraction(
                    presentationInteractionResponse: interactiveAuthorizationResponse.body,
                    authorizationMethods: authorizationMethods,
                    endpoint: endpoint
                )
            } else {
                throw InteractiveAuthorizationException(
                    message: "Unsupported interaction type: \(type)"
                )
            }
            
        } catch let e as InteractiveAuthorizationException {
            Util.logError(message: "Interactive authorization failed: \(e.message)", className: "InteractiveAuthorizationHandler")
            throw e

        } catch let e as VCIClientException {
            Util.logError(message: "Interactive authorization failed: \(e.message)", className: "InteractiveAuthorizationHandler")
            throw InteractiveAuthorizationException(
                message: "Interactive authorization failed: \(e.message)",
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )

        } catch {
            Util.logError(message: "Unexpected error during interactive authorization: \(error.localizedDescription)", className: "InteractiveAuthorizationHandler")
            throw InteractiveAuthorizationException(
                message: "Unexpected error during interactive authorization: \(error.localizedDescription)",
                cause: error
            )
        }
    }
    
    private func buildInitialIarRequest(
        clientMetadata: ClientMetadata,
        credentialConfigurationId: String,
        pkce: PKCESessionManager.PKCESession,
        interactionTypesSupported: [String],
        dpopJkt: String
    ) -> [String: String] {

        let details = [
            AuthorizationDetails(
                type: "openid_credential",
                credentialConfigurationId: credentialConfigurationId
            )
        ]

        return IARInitialRequestBody(
            clientId: clientMetadata.clientId,
            codeChallenge: pkce.codeChallenge,
            redirectUri: clientMetadata.redirectUri,
            authorizationDetails: details,
            interactionTypesSupported: interactionTypesSupported,
            dpopJkt: dpopJkt
        ).toFormMap()
    }
    
    private func extractTypeAndThrowIfError(_ responseBody: String) throws -> String {
        let json = JsonUtils.toMap(responseBody)
        
        if let type = json["type"] as? String {
            return type
        }
        
        if let error = json["error"] as? String {
            let errorDescription = (json["error_description"] as? String) ?? ""
            
            var message = "authorization server error: \(error)"
            if !errorDescription.isEmpty {
                message += " - \(errorDescription)"
            }
            
            throw InteractiveAuthorizationException(
                message: message,
                issuerErrorCode: error,
                issuerErrorDescription: errorDescription
            )
        }
        
        throw InteractiveAuthorizationException(
            message: "Missing 'type' in interaction response from authorization server"
        )
    }
    
    private func handlePresentationInteraction(
        presentationInteractionResponse: String,
        authorizationMethods: [AuthorizationMethod],
        endpoint: String
    ) async throws -> AuthorizationResponse {
        
        guard let parsedPresentationInteractionResponse = try? JsonUtils.deserialize(presentationInteractionResponse, as: PresentationInteractionResponse.self) else {
            throw InteractiveAuthorizationException(message: "Failed to parse presentation interaction response")
        }
        
        do {
            try parsedPresentationInteractionResponse.validate()
        } catch {
            throw InteractiveAuthorizationException(  message: "Invalid presentation interaction response: \(error.localizedDescription)")
        }
        
        guard
            case let .presentationDuringIssuance(jsonLdCanonicalizer, openid4vpWalletConfig, selectCredentialsForPresentation, signVerifiablePresentation) = authorizationMethods.first(where: {
                $0.type == .openId4VpPresentationIAE
            })
        else {
            throw InteractiveAuthorizationException(message: "Presentation callback missing")
        }
        
        let authorizationService = PresentationDuringIssuanceAuthorizationMethodService(
            jsonLdCanonicalizer: jsonLdCanonicalizer,
            openid4vpWalletConfig: openid4vpWalletConfig,
            selectCredentialsForPresentation: selectCredentialsForPresentation,
            signVerifiablePresentation: signVerifiablePresentation,
            networkManager: self.networkManager
        )
        
        return try await authorizationService.authorizeUser(
            requestData: PresentationDuringIssuanceRequestData(
                ovpRequest: parsedPresentationInteractionResponse.openid4vpRequest,
                authSession: parsedPresentationInteractionResponse.authSession ?? "",
                iar: endpoint
            )
        )
    }
}







