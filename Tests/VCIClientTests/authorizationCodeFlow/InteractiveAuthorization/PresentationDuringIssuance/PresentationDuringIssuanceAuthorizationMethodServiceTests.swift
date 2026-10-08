import XCTest
import OpenID4VPBridge
@testable import VCIClient
import OpenID4VP

private final class DummyAuthorizationRequestData: AuthorizationRequestData {}

private final class FakeOpenID4VP: OpenID4VPInteracting {
    enum Behavior {
        case success
        case authThrows(OpenID4VPException)
        case unsignedThrows(Error)
        case constructResponseReturns([String: Any])
    }

    var behavior: Behavior = .success
    var constructedError: Error?

    private let real = OpenID4VP(traceabilityId: "", walletConfig: WalletConfig())

    func authenticateVerifier(
        authRequest authorizationRequest: [String : Any]
    ) async throws -> AuthorizationRequest {

        switch behavior {
        case .authThrows(let ex):
            throw ex
        default:
            return try await real.authenticateVerifier(
                authorizationRequest: authorizationRequest
            )
        }
    }

    func constructUnsignedVPToken(
        selectedCredentials verifiableCredentials: [String : [Credential]]
    ) async throws -> [UnsignedVPToken] {

        switch behavior {
        case .unsignedThrows(let err):
            throw err
        default:
            return []   // safe for service — not inspected
        }
    }

    func constructVPResponse(
        vpTokenSigningResults: [VPTokenSigningResult]
    ) -> [String : Any] {

        switch behavior {
        case .constructResponseReturns(let dict):
            return dict
        default:
            return [
                "vp_token": "signed",
                "presentation_submission": ["id": "ps1"]
            ]
        }
    }

    func constructErrorInfo(exception: Error) -> [String : Any] {
        constructedError = exception
        return [
            "error": "server_error",
            "error_description": "constructed error: \(exception)"
        ]
    }
}

final class PresentationDuringIssuanceAuthorizationMethodServiceTests: XCTestCase {
    
    private let authorizationRequest: [String: Any] = [
        "client_id": "redirect_uri:https://mock-verifier.com",
        "response_uri": "https://mock-verifier.com",
        "presentation_definition": [
            "id": "vp_presentation_definition",
            "input_descriptors": [
                [
                    "id": "input_1",
                    "name": "Verifiable Credential",
                    "purpose": "To verify identity",
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2018"]
                        ]
                    ],
                    "constraints": [
                        "fields": [
                            [
                                "path": ["$.credentialSubject.id"],
                                "filter": [
                                    "type": "string",
                                    "pattern": "did:example:"
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ],
        "response_type": "vp_token",
        "response_mode": "iar-post",
        "nonce": "abc",
        "state": "xyz"
    ]


    private func makeRequestData(
        authSession: String = "auth-session-1",
        iar: String = "https://issuer.example.com/iar",
        ovpRequest: [String: Any]? = nil
    ) -> PresentationDuringIssuanceRequestData {

        PresentationDuringIssuanceRequestData(
            ovpRequest: ovpRequest ?? authorizationRequest,
            authSession: authSession,
            iar: iar
        )
    }

    private func makeService(
        openId4vp: OpenID4VPInteracting,
        network: MockNetworkManager = MockNetworkManager(),
        select: SelectCredentialsForPresentationCallback? = nil,
        sign: SignVerifiablePresentationCallback? = nil
    ) -> PresentationDuringIssuanceAuthorizationMethodService {

        let selectCallback = select ?? { _ in
            return [
                "cred1": [
                    Credential(
                        format: .ldp_vc,
                        data: OpenID4VPAnyCodable(["credentialSubject": ["id": "did:example:123="]]),
                        credentialId: "cred1"
                    )
                ]
            ]
        }

        let signCallback = sign ?? { _ in
            return [] // not inspected by service
        }

        return PresentationDuringIssuanceAuthorizationMethodService(
            jsonLdCanonicalizer: { jsonLd in
                return "Y2Fub25pY2FsaXplZA=="
            },
            openid4vpWalletConfig: WalletConfig(),
            selectCredentialsForPresentation: selectCallback,
            signVerifiablePresentation: signCallback,
            networkManager: network,
            openId4vp: openId4vp
        )
    }

    // MARK: - Basic

    func test_type_returns_openId4VpPresentation() {
        let sut = makeService(openId4vp: FakeOpenID4VP())
        XCTAssertEqual(
            sut.type(),
            InteractionType.openId4VpPresentationIAE.rawValue
        )
    }

    func test_invalidRequestData_throws_error() async {
        let sut = makeService(openId4vp: FakeOpenID4VP())

        await XCTAssertThrowsErrorAsync {
            _ = try await sut.authorizeUser(
                requestData: DummyAuthorizationRequestData()
            )
        } verify: { error in
            XCTAssertTrue(error is InteractiveAuthorizationException)
            XCTAssertEqual(
                error.localizedDescription,
                "Failed to authorize via interaction: Expected PresentationDuringIssuanceRequestData"
            )
        }
    }

    // MARK: - Success

    func test_full_success_flow_returns_success_response() async throws {

        let fake = FakeOpenID4VP()
        let network = MockNetworkManager()

        let success = AuthorizationResponse(
            authorizationCode: "code-123",
            status: "success",
            error: nil,
            errorDescription: nil,
            authSession: "auth-session-1"
        )

        network.responseBody =
        String(data: try JSONEncoder().encode(success), encoding: .utf8)!

        let sut = makeService(
            openId4vp: fake,
            network: network
        )

        let response = try await sut.authorizeUser(
            requestData: makeRequestData()
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(response.authorizationCode, "code-123")
        XCTAssertEqual(network.capturedParams["auth_session"], "auth-session-1")
        XCTAssertNotNil(network.capturedParams["openid4vp_response"])
    }

    func test_full_success_flow_accepts_supported_iae_response_modes() async throws {

        for responseMode in ["iae_post", "iae_post.jwt"] {

            let fake = FakeOpenID4VP()
            let network = MockNetworkManager()

            let success = AuthorizationResponse(
                authorizationCode: "code-123",
                status: "success",
                error: nil,
                errorDescription: nil,
                authSession: "auth-session-1"
            )

            network.responseBody =
                String(data: try JSONEncoder().encode(success), encoding: .utf8)!

            var request = authorizationRequest
            request["response_mode"] = responseMode

            let sut = makeService(
                openId4vp: fake,
                network: network
            )

            let response = try await sut.authorizeUser(
                requestData: makeRequestData(ovpRequest: request)
            )

            XCTAssertEqual(response.status, "success")
            XCTAssertEqual(response.authorizationCode, "code-123")
        }
    }


    // MARK: - Empty selection

    func test_empty_selection_maps_to_access_denied_and_posts() async throws {

        let network = MockNetworkManager()

        let issuerResponse = AuthorizationResponse(
            authorizationCode: nil,
            status: "error",
            error: "access_denied",
            errorDescription: "denied",
            authSession: "auth-session-1"
        )

        network.responseBody =
        String(data: try JSONEncoder().encode(issuerResponse), encoding: .utf8)!

        let sut = makeService(
            openId4vp: FakeOpenID4VP(),
            network: network,
            select: { _ in [:] }
        )

        let response = try await sut.authorizeUser(
            requestData: makeRequestData()
        )

        XCTAssertEqual(response.error, "access_denied")
    }

    func test_unsupported_response_mode_posts_error_without_selecting_credentials() async throws {
        let fake = FakeOpenID4VP()
        let network = MockNetworkManager()
        let issuerResponse = AuthorizationResponse(
            authorizationCode: nil,
            status: "error",
            error: "invalid_request",
            errorDescription: "unsupported response mode",
            authSession: "auth-session-1"
        )
        network.responseBody =
            String(data: try JSONEncoder().encode(issuerResponse), encoding: .utf8)!

        var didSelectCredentials = false
        let sut = makeService(
            openId4vp: fake,
            network: network,
            select: { _ in
                didSelectCredentials = true
                return [:]
            }
        )
        var unsupportedRequest = authorizationRequest
        unsupportedRequest["response_mode"] = "direct_post"

        _ = try await sut.authorizeUser(
            requestData: makeRequestData(ovpRequest: unsupportedRequest)
        )

        XCTAssertFalse(didSelectCredentials)
        XCTAssertEqual(
            fake.constructedError?.localizedDescription,
            "response_mode must be 'iar-post', 'iar-post.jwt', 'iae_post' or 'iae_post.jwt'"
        )
    }

    // MARK: - Network failure

    func test_network_failure_throws_interactive_exception() async {

        let network = MockNetworkManager()
        network.shouldThrowNetworkError = true

        let sut = makeService(
            openId4vp: FakeOpenID4VP(),
            network: network
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await sut.authorizeUser(
                requestData: self.makeRequestData()
            )
        } verify: { error in
            XCTAssertTrue(error is InteractiveAuthorizationException)
            XCTAssertTrue(
                error.localizedDescription.contains(
                    "Error while posting VP response"
                )
            )
        }
    }

    // MARK: - Invalid issuer response

    func test_invalid_issuer_response_throws_deserialization_error() async {

        let network = MockNetworkManager()
        network.responseBody = "not-json"

        let sut = makeService(
            openId4vp: FakeOpenID4VP(),
            network: network
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await sut.authorizeUser(
                requestData: self.makeRequestData()
            )
        } verify: { error in
            XCTAssertTrue(error is InteractiveAuthorizationException)
            XCTAssertEqual(
                error.localizedDescription,
                "Failed to authorize via interaction: Issuer response deserialization failed"
            )
        }
    }
}
