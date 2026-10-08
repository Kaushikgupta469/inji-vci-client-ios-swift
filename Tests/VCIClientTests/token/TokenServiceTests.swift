@testable import VCIClient
import XCTest

final class TokenServiceTests: XCTestCase {
    func test_getAccessToken_withPreAuthCode_success() async throws {
        let mockToken = TokenResponse.mock()
        let json = try JSONEncoder().encode(mockToken)
        let mockResponse = String(data: json, encoding: .utf8)!

        let mockNetwork = MockNetworkManager()
        mockNetwork.responseBody = mockResponse

        let service = TokenService(networkManager: mockNetwork)

        let result = try await service.getAccessToken(
            getTokenResponse: {_ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer")}, tokenEndpoint: "https://example.com/token",
            preAuthCode: "valid-code"
        )

        XCTAssertEqual(result.accessToken, "mock-token")
       
    }

    func test_getAccessToken_withAuthCode_success() async throws {
        let mockToken = TokenResponse.mock()
        let json = try JSONEncoder().encode(mockToken)
        let mockResponse = String(data: json, encoding: .utf8)!
        let mockNetwork = MockNetworkManager()
        mockNetwork.responseBody = mockResponse

        let service = TokenService(networkManager: mockNetwork)

        let result = try await service.getAccessToken(
            getTokenResponse: {_ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer")}, tokenEndpoint: "https://example.com/token",
            authCode: "auth123",
            clientId: "clientABC",
            redirectUri: "app://callback",
            codeVerifier: "verifier123"
        )

        XCTAssertEqual(result.accessToken, "mock-token")
    }

    func test_getAccessToken_attachesDpopProof_whenManagerInitialized() async throws {
        let service = TokenService(networkManager: MockNetworkManager())
        let dpopManager = DPoPManager()
        try dpopManager.initialize(tokenEndpoint: "https://example.com/token", authorizationServerSupportedAlgorithms: ["ES256"])

        var captured: TokenRequest?
        _ = try await service.getAccessToken(
            getTokenResponse: { request in
                captured = request
                return TokenResponse(accessToken: "mock-token", tokenType: "DPoP")
            },
            tokenEndpoint: "https://example.com/token",
            preAuthCode: "valid-code",
            dpopManager: dpopManager
        )

        let proof = try XCTUnwrap(captured?.dpopProof)
        XCTAssertEqual(proof.components(separatedBy: ".").count, 3)
    }

    func test_getAccessToken_leavesDpopProofNil_whenManagerNotInitialized() async throws {
        let service = TokenService(networkManager: MockNetworkManager())

        var captured: TokenRequest?
        _ = try await service.getAccessToken(
            getTokenResponse: { request in
                captured = request
                return TokenResponse(accessToken: "mock-token", tokenType: "Bearer")
            },
            tokenEndpoint: "https://example.com/token",
            preAuthCode: "valid-code"
        )

        XCTAssertNil(captured?.dpopProof)
    }
}
