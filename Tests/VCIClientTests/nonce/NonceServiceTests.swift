import XCTest
@testable import VCIClient

final class NonceServiceTests: XCTestCase {
    func testFetchNonce_returnsParsedNonceAndBuildsExpectedRequest() async throws {
        let networkManager = MockNetworkManager()
        networkManager.responseBody = #"{"c_nonce":"nonce-123"}"#
        let service = NonceService(session: networkManager)

        let nonce = try await service.fetchNonce(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "https://issuer.example.com",
                credentialEndpoint: "https://issuer.example.com/credential",
                credentialFormat: .ldp_vc,
                nonceEndpoint: "https://issuer.example.com/nonce"
            )
        )

        XCTAssertEqual(nonce, "nonce-123")
        XCTAssertEqual(networkManager.capturedUrlRequest?.url?.absoluteString, "https://issuer.example.com/nonce")
        XCTAssertEqual(networkManager.capturedUrlRequest?.httpMethod, "POST")
        XCTAssertEqual(networkManager.capturedUrlRequest?.value(forHTTPHeaderField: Header.accept.rawValue), ContentTypes.applicationJson.rawValue)
        XCTAssertEqual(networkManager.capturedUrlRequest?.value(forHTTPHeaderField: Header.contentType.rawValue), ContentTypes.applicationJson.rawValue)
        XCTAssertEqual(String(data: try XCTUnwrap(networkManager.capturedUrlRequest?.httpBody), encoding: .utf8), "{}")
    }

    func testFetchNonce_withoutNonceEndpoint_returnsNilWithoutSendingRequest() async throws {
        let networkManager = MockNetworkManager()
        networkManager.shouldThrowNetworkError = true
        let service = NonceService(session: networkManager)

        let nonce = try await service.fetchNonce(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "https://issuer.example.com",
                credentialEndpoint: "https://issuer.example.com/credential",
                credentialFormat: .ldp_vc
            )
        )

        XCTAssertNil(nonce)
        XCTAssertNil(networkManager.capturedUrlRequest)
    }

    func testFetchNonce_seedsDpopNonceFromResponseHeader() async throws {
        let networkManager = MockNetworkManager()
        networkManager.responseBody = #"{"c_nonce":"nonce-123"}"#
        networkManager.responseHeaders = ["DPoP-Nonce": "dpop-nonce-xyz"]
        let service = NonceService(session: networkManager)
        let dpopManager = try initializedDpopManager()

        let nonce = try await service.fetchNonce(
            issuerMetadata: nonceIssuerMetadata(),
            dpopManager: dpopManager
        )

        XCTAssertEqual(nonce, "nonce-123")
        XCTAssertEqual(try nonceClaim(of: dpopManager), "dpop-nonce-xyz")
    }

    func testFetchNonce_withoutDpopNonceHeader_leavesDpopNonceUntouched() async throws {
        let networkManager = MockNetworkManager()
        networkManager.responseBody = #"{"c_nonce":"nonce-123"}"#
        let service = NonceService(session: networkManager)
        let dpopManager = try initializedDpopManager()

        _ = try await service.fetchNonce(
            issuerMetadata: nonceIssuerMetadata(),
            dpopManager: dpopManager
        )

        XCTAssertNil(try nonceClaim(of: dpopManager))
    }

    private func nonceIssuerMetadata() -> IssuerMetadata {
        IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialFormat: .ldp_vc,
            nonceEndpoint: "https://issuer.example.com/nonce"
        )
    }

    private func initializedDpopManager() throws -> DPoPManager {
        let manager = DPoPManager()
        try manager.initialize(tokenEndpoint: "https://as.example.com/token", authorizationServerSupportedAlgorithms: ["ES256"])
        return manager
    }

    private func nonceClaim(of dpopManager: DPoPManager) throws -> String? {
        let proof = try dpopManager.generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: "token"
        )
        let payload = try XCTUnwrap(try Data(base64URLEncodedString: proof.components(separatedBy: ".")[1]))
        let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
        return claims["nonce"] as? String
    }

    func testFetchNonce_withInvalidJsonThrowsDownloadFailedException() async {
        let networkManager = MockNetworkManager()
        networkManager.responseBody = #"{"unexpected":"value"}"#
        let service = NonceService(session: networkManager)

        await assertThrowsVCIErrorContainingMessage(
            expectedType: DownloadFailedException.self,
            messageContains: "Failed to parse nonce response"
        ) {
            try await service.fetchNonce(
                issuerMetadata: IssuerMetadata(
                    credentialIssuer: "https://issuer.example.com",
                    credentialEndpoint: "https://issuer.example.com/credential",
                    credentialFormat: .ldp_vc,
                    nonceEndpoint: "https://issuer.example.com/nonce"
                )
            ) as Any
        }
    }
}
