class CredentialOfferFlowHandler {
    private let credentialOfferService: CredentialOfferService
    private let issuerMetadataService: IssuerMetadataService
    private let preAuthFlowService: PreAuthCodeFlowService
    private let authorizationCodeFlowService: AuthorizationCodeFlowService

    init(
        credentialOfferService: CredentialOfferService = CredentialOfferService(),
        issuerMetadataService: IssuerMetadataService = IssuerMetadataService(),
        preAuthFlowService: PreAuthCodeFlowService = PreAuthCodeFlowService(),
        authorizationCodeFlowService: AuthorizationCodeFlowService = AuthorizationCodeFlowService()
    ) {
        self.credentialOfferService = credentialOfferService
        self.issuerMetadataService = issuerMetadataService
        self.preAuthFlowService = preAuthFlowService
        self.authorizationCodeFlowService = authorizationCodeFlowService
    }

    func downloadCredentials(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: TxCodeCallback,
        authorizationMethods: [AuthorizationMethod],
        getTokenResponse: @escaping TokenResponseCallback,
        getProofs: @escaping ProofsCallback,
        onCheckIssuerTrust: CheckIssuerTrustCallback = nil,
        networkSession: NetworkManager = NetworkManager.shared,
        downloadTimeoutInMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> CredentialResponse {
        try await executeDownloadCredentials(
            credentialOffer: credentialOffer,
            clientMetadata: clientMetadata,
            getTxCode: getTxCode,
            authorizationMethods: authorizationMethods,
            onCheckIssuerTrust: onCheckIssuerTrust,
            downloadTimeoutInMillis: downloadTimeoutInMillis
        ) { offer, issuerMetadataResponse, credentialConfigurationId, proofBindingContext in
            switch issuerMetadataResponse.issuerMetadata.specVersion {
            case .v1:
                if offer.isPreAuthorizedFlow {
                    return try await self.preAuthFlowService.requestCredentials(
                        issuerMetadata: issuerMetadataResponse.issuerMetadata,
                        credentialOffer: offer,
                        getTokenResponse: getTokenResponse,
                        getProofs: getProofs,
                        credentialConfigurationId: credentialConfigurationId,
                        proofBindingContext: proofBindingContext,
                        getTxCode: getTxCode,
                        downloadTimeoutInMillis: downloadTimeoutInMillis,
                        dpopManager: dpopManager
                    )
                } else if offer.isAuthorizationCodeFlow {
                    return try await self.authorizationCodeFlowService.requestCredentials(
                        issuerMetadata: issuerMetadataResponse.issuerMetadata,
                        clientMetadata: clientMetadata,
                        authorizationMethods: authorizationMethods,
                        getTokenResponse: getTokenResponse,
                        getProofs: getProofs,
                        credentialConfigurationId: credentialConfigurationId,
                        proofBindingContext: proofBindingContext,
                        credentialOffer: offer,
                        downloadTimeOutInMillis: downloadTimeoutInMillis,
                        session: networkSession,
                        dpopManager: dpopManager
                    )
                } else {
                    throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
                }

            case .draft13:
                let proofJwtCallback: ProofJwtCallback = { proofRequest in
                    let proofs = try await getProofs(proofRequest)
                    guard let jwt = proofs.firstProof else {
                        throw DownloadFailedException("Draft13 issuer requires a single JWT proof")
                    }
                    return jwt
                }
                let draft13Response: CredentialResponseDraft13
                if offer.isPreAuthorizedFlow {
                    draft13Response = try await self.preAuthFlowService.requestCredentialsDraft13(
                        issuerMetadata: issuerMetadataResponse.issuerMetadata,
                        credentialOffer: offer,
                        getTokenResponse: getTokenResponse,
                        getProofJwt: proofJwtCallback,
                        credentialConfigurationId: credentialConfigurationId,
                        proofBindingContext: proofBindingContext,
                        getTxCode: getTxCode,
                        downloadTimeoutInMillis: downloadTimeoutInMillis,
                        dpopManager: dpopManager
                    )
                } else if offer.isAuthorizationCodeFlow {
                    draft13Response = try await self.authorizationCodeFlowService.requestCredentialsDraft13(
                        issuerMetadata: issuerMetadataResponse.issuerMetadata,
                        clientMetadata: clientMetadata,
                        authorizationMethods: authorizationMethods,
                        getTokenResponse: getTokenResponse,
                        getProofJwt: proofJwtCallback,
                        credentialConfigurationId: credentialConfigurationId,
                        proofBindingContext: proofBindingContext,
                        credentialOffer: offer,
                        downloadTimeOutInMillis: downloadTimeoutInMillis,
                        session: networkSession,
                        dpopManager: dpopManager
                    )
                } else {
                    throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
                }
                return CredentialResponse(
                    credentials: [CredentialItem(credential: draft13Response.credential)],
                    credentialIssuer: draft13Response.credentialIssuer,
                    credentialConfigurationId: draft13Response.credentialConfigurationId
                )
            }
        }
    }

    private func executeDownloadCredentials<Response>(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: TxCodeCallback,
        authorizationMethods: [AuthorizationMethod],
        onCheckIssuerTrust: CheckIssuerTrustCallback,
        downloadTimeoutInMillis: Int64,
        executeFlow: (CredentialOffer, IssuerMetadataResult, String, ProofBindingContext) async throws -> Response
    ) async throws -> Response {
        let offer = try await credentialOfferService.fetchCredentialOffer(credentialOffer)

        if offer.credentialConfigurationIds.count > 1 {
            throw DownloadFailedException("Batch credential request is not supported")
        }

        let credentialConfigurationId = offer.credentialConfigurationIds.first ?? ""
        let issuerMetadataResponse = try await issuerMetadataService.fetchIssuerMetadataResult(
            credentialIssuer: offer.credentialIssuer,
            credentialConfigurationId: credentialConfigurationId
        )

        let issuerDisplay = (issuerMetadataResponse.raw["display"] as? [[String: Any]]) ?? [[:]]
        try await ensureIssuerTrust(
            credentialIssuer: offer.credentialIssuer,
            issuerDisplay: issuerDisplay,
            onCheckIssuerTrust: onCheckIssuerTrust
        )

        let proofBindingContext = issuerMetadataResponse.toProofBindingContext(
            credentialConfigurationId: credentialConfigurationId
        )

        return try await executeFlow(
            offer,
            issuerMetadataResponse,
            credentialConfigurationId,
            proofBindingContext
        )
    }

    private func ensureIssuerTrust(
        credentialIssuer: String,
        issuerDisplay: [[String: Any]],
        onCheckIssuerTrust: CheckIssuerTrustCallback
    ) async throws {
        guard let onCheck = onCheckIssuerTrust else { return }

        let consented = try await onCheck(credentialIssuer, issuerDisplay)
        if !consented {
            throw CredentialOfferFetchFailedException("Issuer not trusted by user")
        }
    }
}
