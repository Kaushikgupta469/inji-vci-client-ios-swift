import XCTest
@testable import VCIClient

final class VCIClientTests: XCTestCase {
    func testFetchCredentialsUsingCredentialOffer_success() async throws {
        let mockHandler = MockCredentialOfferHandler()
        let client = VCIClient(
            traceabilityId: "test",
            credentialOfferHandler: mockHandler
        )

        let result = try await client.fetchCredentialsUsingCredentialOffer(
            credentialOffer: "mock-offer",
            clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
            getTxCode: { _, _, _ in "mock-tx-code" },
            authorizationMethods: [
                .redirectToWeb(openWebPage: { _ in ["code": "auth-code"] })
            ],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertEqual(result.credentials?.count, 1)
        XCTAssertTrue(mockHandler.didCallDownload)
    }

    func testFetchCredentialsUsingCredentialOffer_failure() async {
        let mockHandler = MockCredentialOfferHandler()
        mockHandler.shouldThrow = true
        let client = VCIClient(
            traceabilityId: "test",
            credentialOfferHandler: mockHandler
        )

        await assertThrowsVCIErrorContainingMessage(
            expectedType: VCIClientException.self,
            expectedCode: "VCI-002",
            messageContains: "Simulated failure"
        ) {
            try await client.fetchCredentialsUsingCredentialOffer(
                credentialOffer: "mock-offer",
                clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
                getTxCode: { _, _, _ in "mock-tx-code" },
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "auth-code"] })
                ],
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
            )
        }
    }

    func testFetchCredentialsFromTrustedIssuer_success() async throws {
        let mockHandler = MockTrustedIssuerHandler()
        let client = VCIClient(
            traceabilityId: "test",
            trustedIssuerFlowHandler: mockHandler
        )

        let result = try await client.fetchCredentialsFromTrustedIssuer(
            credentialIssuer: "mock",
            credentialConfigurationId: "mock-id",
            clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
            getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
            authorizationMethods: [
                .redirectToWeb(openWebPage: { _ in ["code": "auth-code"] })
            ],
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertEqual(result.credentials?.count, 1)
        XCTAssertTrue(mockHandler.didCallDownload)
    }

    func testFetchCredentialsFromTrustedIssuer_failure() async {
        let mockHandler = MockTrustedIssuerHandler()
        mockHandler.shouldThrow = true
        let client = VCIClient(
            traceabilityId: "test",
            trustedIssuerFlowHandler: mockHandler
        )

        await assertThrowsVCIErrorContainingMessage(
            expectedType: VCIClientException.self,
            expectedCode: "VCI-002",
            messageContains: "Simulated failure"
        ) {
            try await client.fetchCredentialsFromTrustedIssuer(
                credentialIssuer: "mock",
                credentialConfigurationId: "mock-id",
                clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "auth-code"] })
                ],
                getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
            )
        }
    }

    func testGetIssuerMetadata_success() async throws {
        let mockIssuerMetadataService = MockIssuerMetadataService(session: MockNetworkManager())
        mockIssuerMetadataService.resultToReturn = IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "mock",
                credentialEndpoint: "mock",
                credentialFormat: .ldp_vc
            ),
            raw: ["issuerName": "TestIssuer"]
        )

        let client = VCIClient(
            traceabilityId: "test",
            issuerMetadataService: mockIssuerMetadataService
        )

        let result = try await client.getIssuerMetadata(credentialIssuer: "https://issuer.example.com")

        XCTAssertEqual(result["issuerName"] as? String, "TestIssuer")
    }

    func testGetIssuerMetadata_failure() async {
        let mockIssuerMetadataService = MockIssuerMetadataService(session: MockNetworkManager())
        mockIssuerMetadataService.shouldThrow = true

        let client = VCIClient(
            traceabilityId: "test",
            issuerMetadataService: mockIssuerMetadataService
        )

        await assertThrowsVCIErrorContainingMessage(
            expectedType: VCIClientException.self,
            expectedCode: "VCI-009",
            messageContains: "Mock error"
        ) {
            try await client.getIssuerMetadata(credentialIssuer: "https://issuer.example.com")
        }
    }

    func testGetCredentialConfigurationsSupported_success() async throws {
        let mockService = MockIssuerMetadataService(session: MockNetworkManager())
        mockService.configurationsToReturn = [
            "vc1": ["format": "ldp_vc"],
            "vc2": ["format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"]
        ]

        let client = VCIClient(
            traceabilityId: "test",
            issuerMetadataService: mockService
        )

        let configs = try await client.getCredentialConfigurationsSupported(
            credentialIssuer: "https://issuer.example.com"
        )

        XCTAssertEqual(configs.count, 2)
        XCTAssertEqual((configs["vc1"] as? [String: Any])?["format"] as? String, "ldp_vc")
        XCTAssertEqual((configs["vc2"] as? [String: Any])?["doctype"] as? String, "org.iso.18013.5.1.mDL")
    }

    func testGetCredentialConfigurationsSupported_failure() async {
        let mockService = MockIssuerMetadataService(session: MockNetworkManager())
        mockService.shouldThrow = true

        let client = VCIClient(
            traceabilityId: "test",
            issuerMetadataService: mockService
        )

        _ = await assertThrowsVCIErrorContainingMessage(
            expectedType: VCIClientException.self,
            expectedCode: "VCI-009",
            messageContains: "Simulated failure"
        ) {
            try await client.getCredentialConfigurationsSupported(
                credentialIssuer: "https://issuer.example.com"
            )
        }
    }

    // MARK: - generateTokenDPoPProof

    func testGenerateTokenDPoPProof_throwsWhenNoActiveFlow() {
        let client = VCIClient(traceabilityId: "test")
        XCTAssertThrowsError(try client.generateTokenDPoPProof(dpopNonce: "nonce")) { error in
            XCTAssertEqual((error as? VCIClientException)?.code, "VCI-013")
        }
    }

    func testGenerateTokenDPoPProof_returnsValidProofWhenFlowIsActive() throws {
        let manager = DPoPManager()
        try manager.initialize(tokenEndpoint: "https://as.example.com/token", authorizationServerSupportedAlgorithms: ["ES256"])
        let client = VCIClient(traceabilityId: "test", dpopManager: manager)

        let proof = try client.generateTokenDPoPProof(dpopNonce: "test-nonce")

        let parts = proof.components(separatedBy: ".")
        XCTAssertEqual(parts.count, 3)

        let headerData = try XCTUnwrap(Data(base64URLEncodedString: parts[0]))
        let header = try XCTUnwrap(JSONSerialization.jsonObject(with: headerData) as? [String: Any])
        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")

        let claimsData = try XCTUnwrap(Data(base64URLEncodedString: parts[1]))
        let claims = try XCTUnwrap(JSONSerialization.jsonObject(with: claimsData) as? [String: Any])
        XCTAssertEqual(claims["nonce"] as? String, "test-nonce")
        XCTAssertEqual(claims["htm"] as? String, "POST")
    }

    func testFetchCredentialsUsingCredentialOffer_resetsDpopSessionAfterFlowCompletes() async throws {
        let manager = DPoPManager()
        let handler = MockCredentialOfferHandler()
        handler.shouldInitializeDpopDuringDownload = true
        let client = VCIClient(traceabilityId: "test", credentialOfferHandler: handler, dpopManager: manager)

        _ = try await client.fetchCredentialsUsingCredentialOffer(
            credentialOffer: "credential-offer",
            clientMetadata: ClientMetadata(clientId: "wallet", redirectUri: "https://wallet.example.com/callback"),
            getTxCode: nil,
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse(accessToken: "token", tokenType: "DPoP") },
            getProofs: { _ in CredentialRequestProofs(proofs: []) }
        )

        XCTAssertThrowsError(try client.generateTokenDPoPProof(dpopNonce: "nonce")) { error in
            XCTAssertEqual((error as? VCIClientException)?.code, "VCI-013")
        }
    }
}
