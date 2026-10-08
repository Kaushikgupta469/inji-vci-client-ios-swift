import XCTest
import OpenID4VPBridge
@testable import VCIClient

final class InteractiveAuthorizationHandlerTests: XCTestCase {

    // MARK: - Helpers

    private func makeClientMetadata() -> ClientMetadata {
        ClientMetadata(clientId: "client-123", redirectUri: "app://callback")
    }

    private func makePKCE() -> PKCESessionManager.PKCESession {
        PKCESessionManager.PKCESession(
            codeVerifier: "verifier",
            codeChallenge: "challenge",
            state: "state",
            nonce: "nonce"
        )
    }

    private func makeAuthMethods(
        select: @escaping SelectCredentialsForPresentationCallback,
        sign: @escaping SignVerifiablePresentationCallback
    ) -> [AuthorizationMethod] {
        [
            .presentationDuringIssuance(
                jsonLdCanonicalizer: { data in
                    return "Y2Fub25pY2FsaXplZA=="
                }, selectCredentialsForPresentation: select,
                signVerifiablePresentation: sign
            )
        ]
    }

    // MARK: - Success path

    func test_handle_success_openId4VpPresentation_flow() async throws {

        let initialNetwork = MockNetworkManager()

        let presentationJSON: [String: Any] = [
            "status": "require_interaction",
            "type": InteractionType.openId4VpPresentation.rawValue,
            "auth_session": "auth-session-1",
            "openid4vp_request": [
                "response_type": "vp_token",
                "response_mode": "iar-post"
            ]
        ]

        let initialBody = try JSONSerialization.data(withJSONObject: presentationJSON)
        initialNetwork.responseBody = String(data: initialBody, encoding: .utf8) ?? ""

        let select: SelectCredentialsForPresentationCallback = { _ in
            return [
                "cred1": [
                    OpenID4VPCredential(
                        format: .ldp_vc,
                        data: OpenID4VPAnyCodable("dummy-cred"),
                        credentialId: "cred1"
                    )
                ]
            ]
        }

        let sign: SignVerifiablePresentationCallback = { _ in
            return [] // Not inspected
        }

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        let response = try await handler.handle(
            endpoint: "https://issuer.example.com/iar",
            clientMetadata: self.makeClientMetadata(),
            credentialConfigurationId: "cfg-1",
            authorizationMethods: makeAuthMethods(select: select, sign: sign),
            pkceSession: self.makePKCE(),
            dpopJkt: "test-jkt"
        )

        XCTAssertEqual(response.status, "require_interaction")
        XCTAssertEqual(response.authSession, "auth-session-1")
    }

    func test_handle_success_openId4VpPresentationIAE_flow() async throws {

        let initialNetwork = MockNetworkManager()

        let presentationJSON: [String: Any] = [
            "status": "require_interaction",
            "type": InteractionType.openId4VpPresentationIAE.rawValue,
            "auth_session": "auth-session-1",
            "openid4vp_request": [
                "response_type": "vp_token",
                "response_mode": "iar-post"
            ]
        ]

        let initialBody = try JSONSerialization.data(withJSONObject: presentationJSON)
        initialNetwork.responseBody = String(data: initialBody, encoding: .utf8) ?? ""

        let select: SelectCredentialsForPresentationCallback = { _ in
            return [
                "cred1": [
                    OpenID4VPCredential(
                        format: .ldp_vc,
                        data: OpenID4VPAnyCodable("dummy-cred"),
                        credentialId: "cred1"
                    )
                ]
            ]
        }

        let sign: SignVerifiablePresentationCallback = { _ in
            return []
        }

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        let response = try await handler.handle(
            endpoint: "https://issuer.example.com/iar",
            clientMetadata: self.makeClientMetadata(),
            credentialConfigurationId: "cfg-1",
            authorizationMethods: makeAuthMethods(select: select, sign: sign),
            pkceSession: self.makePKCE(),
            dpopJkt: "test-jkt"
        )

        XCTAssertEqual(response.status, "require_interaction")
        XCTAssertEqual(response.authSession, "auth-session-1")
    }

    // MARK: - Failure: invalid JSON

    func test_handle_extractInteractionType_invalidJSON_throws() async {

        let initialNetwork = MockNetworkManager()
        initialNetwork.responseBody = "not json"

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        await XCTAssertThrowsErrorAsync {
            _ = try await handler.handle(
                endpoint: "https://issuer.example.com/iar",
                clientMetadata: self.makeClientMetadata(),
                credentialConfigurationId: "cfg-1",
                authorizationMethods: self.makeAuthMethods(select: { _ in [:] }, sign: { _ in [] }),
                pkceSession: self.makePKCE(),
                dpopJkt: "test-jkt"
            )
        } verify: { error in
            let iae = error as? InteractiveAuthorizationException
            XCTAssertNotNil(iae)
            XCTAssertTrue(
                iae?.message.contains("Missing 'type'") == true
            )
        }
    }

    // MARK: - Unsupported interaction type

    func test_handle_unsupported_interaction_type_throws() async {

        let initialNetwork = MockNetworkManager()
        let json = ["type": "unknown_type"]
        let data = try! JSONSerialization.data(withJSONObject: json)
        initialNetwork.responseBody = String(data: data, encoding: .utf8) ?? ""

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        await XCTAssertThrowsErrorAsync {
            _ = try await handler.handle(
                endpoint: "https://issuer.example.com/iar",
                clientMetadata: self.makeClientMetadata(),
                credentialConfigurationId: "cfg-1",
                authorizationMethods: self.makeAuthMethods(select: { _ in [:] }, sign: { _ in [] }),
                pkceSession: self.makePKCE(),
                dpopJkt: "test-jkt"
            )
        } verify: { error in
            let iae = error as? InteractiveAuthorizationException
            XCTAssertNotNil(iae)
            XCTAssertTrue(
                iae?.message.contains("Unsupported interaction type") == true
            )
        }
    }

    // MARK: - Deserialize nil

    func test_handlePresentationInteraction_deserialize_nil_throws() async {

        let initialNetwork = MockNetworkManager()

        let json: [String: Any] = [
            "type": InteractionType.openId4VpPresentation.rawValue,
            "status": "require_interaction"
        ]

        let data = try! JSONSerialization.data(withJSONObject: json)
        initialNetwork.responseBody = String(data: data, encoding: .utf8) ?? ""

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        await XCTAssertThrowsErrorAsync {
            _ = try await handler.handle(
                endpoint: "https://issuer.example.com/iar",
                clientMetadata: self.makeClientMetadata(),
                credentialConfigurationId: "cfg-1",
                authorizationMethods: self.makeAuthMethods(select: { _ in [:] }, sign: { _ in [] }),
                pkceSession: self.makePKCE(),
                dpopJkt: "test-jkt"
            )
        } verify: { error in
            let iae = error as? InteractiveAuthorizationException
            XCTAssertNotNil(iae)
            XCTAssertTrue(
                iae?.message.contains("Failed to parse presentation interaction response") == true
            )
        }
    }

    // MARK: - Validation failure

    func test_handlePresentationInteraction_validate_throws() async {

        let initialNetwork = MockNetworkManager()

        let json: [String: Any] = [
            "type": InteractionType.openId4VpPresentation.rawValue,
            "status": "require_interaction",
            "auth_session": "s",
            "openid4vp_request": [:]
        ]

        let data = try! JSONSerialization.data(withJSONObject: json)
        initialNetwork.responseBody = String(data: data, encoding: .utf8) ?? ""

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        await XCTAssertThrowsErrorAsync {
            _ = try await handler.handle(
                endpoint: "https://issuer.example.com/iar",
                clientMetadata: self.makeClientMetadata(),
                credentialConfigurationId: "cfg-1",
                authorizationMethods: self.makeAuthMethods(select: { _ in [:] }, sign: { _ in [] }),
                pkceSession: self.makePKCE(),
                dpopJkt: "test-jkt"
            )
        } verify: { error in
            let iae = error as? InteractiveAuthorizationException
            XCTAssertNotNil(iae)
            XCTAssertTrue(
                iae?.message.contains("Invalid presentation interaction response") == true
            )
        }
    }

    // MARK: - Network error on initial IAR

    func test_throws_error_during_network_error_on_initial_iar_request() async {

        let initialNetwork = MockNetworkManager()
        initialNetwork.shouldThrowNetworkError = true

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        await XCTAssertThrowsErrorAsync {
            _ = try await handler.handle(
                endpoint: "https://issuer.example.com/iar",
                clientMetadata: self.makeClientMetadata(),
                credentialConfigurationId: "cfg-1",
                authorizationMethods: self.makeAuthMethods(select: { _ in [:] }, sign: { _ in [] }),
                pkceSession: self.makePKCE(),
                dpopJkt: "test-jkt"
            )
        } verify: { error in
            let iae = error as? InteractiveAuthorizationException
            XCTAssertNotNil(iae)
            XCTAssertTrue(
                iae?.message.contains("Interactive authorization failed") == true
            )
        }
    }

    // MARK: - dpop_jkt binding

    func test_handle_includesDpopJkt_inInitialIarRequest_whenProvided() async {

        let initialNetwork = MockNetworkManager()
        let data = try! JSONSerialization.data(withJSONObject: ["type": "unknown_type"])
        initialNetwork.responseBody = String(data: data, encoding: .utf8) ?? ""

        let handler = InteractiveAuthorizationHandler(networkManager: initialNetwork)

        await XCTAssertThrowsErrorAsync {
            _ = try await handler.handle(
                endpoint: "https://issuer.example.com/iar",
                clientMetadata: self.makeClientMetadata(),
                credentialConfigurationId: "cfg-1",
                authorizationMethods: self.makeAuthMethods(select: { _ in [:] }, sign: { _ in [] }),
                pkceSession: self.makePKCE(),
                dpopJkt: "test-thumbprint"
            )
        } verify: { _ in }

        XCTAssertEqual(initialNetwork.capturedParams["dpop_jkt"], "test-thumbprint")
    }
}
