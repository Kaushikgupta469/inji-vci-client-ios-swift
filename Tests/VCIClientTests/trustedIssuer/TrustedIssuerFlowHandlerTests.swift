import XCTest
@testable import VCIClient


final class TrustedIssuerHandlerTests: XCTestCase {
    func testDownloadCredentials_returnsResponse() async throws {
        let mockService = MockAuthorizationCodeFlowService()
        mockService.responseToReturn = CredentialResponseDraft13(credential: .init("mock"), credentialIssuer: "mock-issuer", credentialConfigurationId: "mock")
        let mockIssuerMetadataService = MockIssuerMetadataService(session: MockNetworkManager())
        mockIssuerMetadataService.resultToReturn = IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "issuer",
                credentialEndpoint: "mock",
                credentialFormat: .ldp_vc,
                specVersion: .draft13
            ),
            raw: ["credential": "mock"]
        )

        let handler = TrustedIssuerFlowHandler(authService: mockService, issuerMetadataService: mockIssuerMetadataService)

        let result = try await handler.downloadCredentials(
            credentialIssuer: "mock-issuer",
            credentialConfigurationId: "mock",
            clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
            authorizationMethods: [AuthorizationMethod.redirectToWeb(openWebPage: {_ in ["code": "auth_code"]})],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer", expiresIn: nil) },
            getProofs: { _ in CredentialRequestProofs(proofs: ["jwt"]) }
        )

        XCTAssertTrue(mockService.didCallRequestCredentials)
        let actualData = try result.toJsonString().data(using: String.Encoding.utf8)
        let actualJson = try JSONSerialization.jsonObject(with: actualData!, options: []) as? [String: Any]

        let expectedJson: [String: Any] = [
            "credentials": [["credential": "mock"]],
            "credential_issuer": "mock-issuer",
            "credential_configuration_id": "mock"
        ]

        XCTAssertEqual(actualJson! as NSDictionary, expectedJson as NSDictionary)

    }

    func testDownloadCredentials_withNonceEndpoint_routesToV1() async throws {
        let mockService = MockAuthorizationCodeFlowService()
        let mockIssuerMetadataService = MockIssuerMetadataService(session: MockNetworkManager())
        mockIssuerMetadataService.resultToReturn = IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "issuer",
                credentialEndpoint: "mock",
                credentialFormat: .ldp_vc,
                nonceEndpoint: "https://issuer.com/nonce"
            ),
            raw: [:]
        )

        let handler = TrustedIssuerFlowHandler(authService: mockService, issuerMetadataService: mockIssuerMetadataService)

        let result = try await handler.downloadCredentials(
            credentialIssuer: "mock-issuer",
            credentialConfigurationId: "mock",
            clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertTrue(mockService.didCallRequestCredentials)
        XCTAssertNotNil(result.credentials) // V1 mock returns credentials array
    }

    func testDownloadCredentials_withoutNonceEndpoint_routesToDraft13() async throws {
        let mockService = MockAuthorizationCodeFlowService()
        mockService.responseToReturn = CredentialResponseDraft13(
            credential: .init("draft13-credential"),
            credentialIssuer: "mock-issuer",
            credentialConfigurationId: "mock"
        )
        let mockIssuerMetadataService = MockIssuerMetadataService(session: MockNetworkManager())
        mockIssuerMetadataService.resultToReturn = IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "issuer",
                credentialEndpoint: "mock",
                credentialFormat: .ldp_vc,
                specVersion: .draft13
            ),
            raw: [:]
        )

        let handler = TrustedIssuerFlowHandler(authService: mockService, issuerMetadataService: mockIssuerMetadataService)

        let result = try await handler.downloadCredentials(
            credentialIssuer: "mock-issuer",
            credentialConfigurationId: "mock",
            clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertTrue(mockService.didCallRequestCredentials)
        XCTAssertEqual(result.credentials?.count, 1)
        XCTAssertEqual(result.credentials?.first?.credential?.value as? String, "draft13-credential")
        XCTAssertEqual(result.credentialIssuer, "mock-issuer")
        XCTAssertEqual(result.credentialConfigurationId, "mock")
    }

    func testDownloadCredentials_propagatesError() async {
        let mockAuthorizationCodeFlowService = MockAuthorizationCodeFlowService()
        let mockIssuerMetadataService = MockIssuerMetadataService(session: MockNetworkManager())
        mockIssuerMetadataService.resultToReturn = IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "issuer",
                credentialEndpoint: "mock",
                credentialFormat: .ldp_vc,
                specVersion: .draft13
            ),
            raw: ["credential": "mock"]
        )
        mockAuthorizationCodeFlowService.shouldThrow = true

        let handler = TrustedIssuerFlowHandler(authService: mockAuthorizationCodeFlowService, issuerMetadataService: mockIssuerMetadataService)

        do {
            _ = try await handler.downloadCredentials(
                credentialIssuer: "mock-issuer",
                credentialConfigurationId: "mock",
                clientMetadata: ClientMetadata(clientId: "", redirectUri: ""),
                authorizationMethods: [AuthorizationMethod.redirectToWeb(openWebPage: {_ in ["code": "auth_code"]})],
                getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer", expiresIn: nil) },
                getProofs: { _ in CredentialRequestProofs(proofs: ["jwt"]) }
            )
            XCTFail("Expected error but got success")
        } catch let error as VCIClientException {
            XCTAssertEqual(error.code, "VCI-009")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}
