@testable import VCIClient
import XCTest

final class PushedAuthorizationRequestServiceTests: XCTestCase {

    private let parEndpoint = "https://as.example.com/as/par"
    private let validResponseBody =
        "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:abc\",\"expires_in\":90}"

    private func makeMock(responseBody: String) -> MockNetworkManager {
        let mock = MockNetworkManager()
        mock.responseBody = responseBody
        return mock
    }

    func test_success_returnsRequestUriAndExpiresIn() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        let result = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            session: mock
        )

        XCTAssertEqual(result.requestUri, "urn:ietf:params:oauth:request_uri:abc")
        XCTAssertEqual(result.expiresIn, 90)
    }

    func test_alwaysIncludesCoreParamsIncludingNonce() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            session: mock
        )

        let body = mock.capturedParams
        XCTAssertEqual(body["response_type"], "code")
        XCTAssertEqual(body["client_id"], "client-id")
        XCTAssertEqual(body["redirect_uri"], "app://callback")
        XCTAssertEqual(body["code_challenge"], "challenge")
        XCTAssertEqual(body["code_challenge_method"], "S256")
        XCTAssertEqual(body["state"], "state-123")
        XCTAssertEqual(body["nonce"], "nonce-123")
    }

    func test_sendsScopeAndNeverAuthorizationDetails() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            session: mock
        )

        let body = mock.capturedParams
        XCTAssertEqual(body["scope"], "openid")
        XCTAssertNil(body["authorization_details"])
    }

    func test_sendsDpopJktWhenProvided() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            dpopJkt: "jkt-thumbprint",
            session: mock
        )

        XCTAssertEqual(mock.capturedParams["dpop_jkt"], "jkt-thumbprint")
    }

    func test_omitsDpopJktWhenNotProvided() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            session: mock
        )

        XCTAssertNil(mock.capturedParams["dpop_jkt"])
    }

    func test_mergesClientAuthParamsIntoBody() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            clientAuthParams: [
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": "signed.jwt.value",
            ],
            session: mock
        )

        let body = mock.capturedParams
        XCTAssertEqual(
            body["client_assertion_type"],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        )
        XCTAssertEqual(body["client_assertion"], "signed.jwt.value")
    }

    func test_clientAuthParamsMustNotOverwriteCoreParams() async throws {
        let mock = makeMock(responseBody: validResponseBody)

        _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint: parEndpoint,
            clientId: "real-client-id",
            redirectUri: "app://callback",
            codeChallenge: "challenge",
            state: "state-123",
            nonce: "nonce-123",
            scope: "openid",
            clientAuthParams: ["client_id": "malicious-id"],
            session: mock
        )

        XCTAssertEqual(mock.capturedParams["client_id"], "real-client-id")
    }

    func test_throwsWhenResponseHasNoRequestUri() async {
        let mock = makeMock(responseBody: "{}")

        do {
            _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
                parEndpoint: parEndpoint,
                clientId: "client-id",
                redirectUri: "app://callback",
                codeChallenge: "challenge",
                state: "state-123",
                nonce: "nonce-123",
                scope: "openid",
                session: mock
            )
            XCTFail("Expected PushedAuthorizationRequestException to be thrown")
        } catch is PushedAuthorizationRequestException {
            // expected
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func test_wrapsServerErrorAndPropagatesIssuerErrorCode() async {
        let mock = ThrowingPARNetworkManager()

        do {
            _ = try await PushedAuthorizationRequestService().pushAuthorizationRequest(
                parEndpoint: parEndpoint,
                clientId: "client-id",
                redirectUri: "app://callback",
                codeChallenge: "challenge",
                state: "state-123",
                nonce: "nonce-123",
                scope: "openid",
                session: mock
            )
            XCTFail("Expected PushedAuthorizationRequestException to be thrown")
        } catch let ex as PushedAuthorizationRequestException {
            XCTAssertEqual(ex.issuerErrorCode, "invalid_client")
            XCTAssertEqual(ex.issuerErrorDescription, "Client authentication failed")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}

// Mock that simulates a non-2xx PAR response surfaced as NetworkRequestFailedException.
private final class ThrowingPARNetworkManager: NetworkManager {
    override func sendRequest(
        url: String,
        method: HttpMethod,
        headers: [String: String]?,
        bodyParams: [String: String]?,
        timeoutMillis: Int64
    ) async throws -> NetworkResponse {
        throw NetworkRequestFailedException(
            message: "HTTP 401",
            issuerErrorCode: "invalid_client",
            issuerErrorDescription: "Client authentication failed"
        )
    }
}
