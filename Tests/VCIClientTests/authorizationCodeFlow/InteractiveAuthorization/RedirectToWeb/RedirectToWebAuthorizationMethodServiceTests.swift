@testable import VCIClient
import XCTest

final class RedirectToWebAuthorizationMethodServiceTests: XCTestCase {

    // MARK: - Helpers

    private func makeValidRequestData(
        authorizeUrl: String = "https://auth.example.com/authorize",
        clientId: String = "client-123",
        redirectUri: String = "https://wallet.example.com/callback",
        scope: String = "openid profile",
        codeVerifier: String = "verifier-abc",
        codeChallenge: String = "challenge-xyz",
        state: String = "state-123",
        nonce: String = "nonce-456",
        pushedAuthorizationRequestEndpoint: String? = nil,
        requirePushedAuthorizationRequests: Bool? = nil
    ) -> ImplicitAuthorizationRequestData {
        let clientMetadata = ClientMetadata(clientId: clientId, redirectUri: redirectUri)
        let pkceSession = PKCESessionManager.PKCESession(
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge,
            state: state,
            nonce: nonce
        )
        return ImplicitAuthorizationRequestData(
            authorizeUrl: authorizeUrl,
            clientMetadata: clientMetadata,
            pkceSession: pkceSession,
            scope: scope,
            pushedAuthorizationRequestEndpoint: pushedAuthorizationRequestEndpoint,
            requirePushedAuthorizationRequests: requirePushedAuthorizationRequests,
            dpopJkt: "test-jkt"
        )
    }

    // MARK: - Tests

    func test_type_returnsRedirectToWeb() {
        let service = RedirectToWebAuthorizationMethodService { _ in [:] }
        XCTAssertEqual(service.type(), InteractionType.redirectToWeb.rawValue)
    }

    func test_authorizeUser_withInvalidRequestData_throwsIllegalArgument() async {
        let service = RedirectToWebAuthorizationMethodService { _ in [:] }
        let invalidRequest = DummyAuthorizationRequestData()

        do {
            _ = try await service.authorizeUser(requestData: invalidRequest)
            XCTFail("Expected IllegalArgumentException to be thrown")
        } catch is InteractiveAuthorizationException {
            // expected
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func test_authorizeUser_withErrorResponse_mapsToErrorAuthorizationResponse() async throws {
        let service = RedirectToWebAuthorizationMethodService { _ in
            [
                "error": "access_denied",
                "error_description": "User denied access"
            ]
        }
        let request = makeValidRequestData()

        let response = try await service.authorizeUser(requestData: request)

        XCTAssertEqual(response.status, "error")
        XCTAssertEqual(response.error, "access_denied")
        XCTAssertEqual(response.errorDescription, "User denied access")
        XCTAssertNil(response.authorizationCode)
        XCTAssertNil(response.authSession)
    }

    func test_authorizeUser_withMissingCode_throwsInteractiveAuthorizationException() async {
        let service = RedirectToWebAuthorizationMethodService { _ in [:] }
        let request = makeValidRequestData()

        do {
            _ = try await service.authorizeUser(requestData: request)
            XCTFail("Expected InteractiveAuthorizationException to be thrown")
        } catch is InteractiveAuthorizationException {
            // expected
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func test_authorizeUser_withValidCode_returnsSuccessAndAuthSession() async throws {
        let service = RedirectToWebAuthorizationMethodService { _ in
            [
                "code": "authcode123",
                "auth_session": "session456"
            ]
        }
        let request = makeValidRequestData()

        let response = try await service.authorizeUser(requestData: request)

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(response.authorizationCode, "authcode123")
        XCTAssertEqual(response.authSession, "session456")
        XCTAssertNil(response.error)
        XCTAssertNil(response.errorDescription)
    }

    func test_authorizeUser_passesCorrectAuthorizationUrlToCallback() async throws {
        // Arrange expected inputs
        let authorizeUrl = "https://auth.example.com/authorize"
        let clientId = "my-client"
        let redirectUri = "myapp://callback"
        let scope = "openid email"
        let codeVerifier = "code-verifier"
        let codeChallenge = "code-challenge"
        let state = "state-xyz"
        let nonce = "nonce-abc"

        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService { url in
            capturedUrl = url
            // Return an error so the service returns early; we only care about the URL here.
            return ["error": "access_denied"]
        }

        let request = makeValidRequestData(
            authorizeUrl: authorizeUrl,
            clientId: clientId,
            redirectUri: redirectUri,
            scope: scope,
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge,
            state: state,
            nonce: nonce
        )

        // Act
        _ = try await service.authorizeUser(requestData: request)

        // Assert
        guard let urlString = capturedUrl, let components = URLComponents(string: urlString) else {
            return XCTFail("Expected a valid URL to be passed to OpenWebPageCallback")
        }

        XCTAssertEqual("\(components.scheme ?? "")://\(components.host ?? "")\(components.path)", authorizeUrl)

        let items = components.queryItems ?? []
        let query: [String: String] = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })

        XCTAssertEqual(query["client_id"], clientId)
        XCTAssertEqual(query["redirect_uri"], redirectUri)
        XCTAssertEqual(query["response_type"], "code")
        XCTAssertEqual(query["scope"], scope)
        XCTAssertEqual(query["state"], state)
        XCTAssertEqual(query["code_challenge"], codeChallenge)
        // Accept either s256 or S256 (implementation may choose case)
        if let method = query["code_challenge_method"] {
            XCTAssertEqual(method.lowercased(), "s256")
        } else {
            XCTFail("Missing code_challenge_method")
        }
        XCTAssertEqual(query["nonce"], nonce)
    }

    func test_authorizeUser_whenParIsMandatory_usesPushedRequest() async throws {
        let parService = StubPARService(
            result: .success(
                PushedAuthorizationResponse(requestUri: "urn:req:abc", expiresIn: 90)
            )
        )
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(
            requestData: makeValidRequestData(
                pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par",
                requirePushedAuthorizationRequests: true
            )
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 1)
        XCTAssertTrue(capturedUrl?.contains("request_uri=urn:req:abc") ?? false)
    }

    func test_authorizeUser_whenParIsMandatoryAndParFails_throwsWithoutFallback() async {
        let parService = StubPARService(
            result: .failure(PushedAuthorizationRequestException(message: "HTTP 400"))
        )
        var callbackInvoked = false
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { _ in
                callbackInvoked = true
                return ["code": "authcode123"]
            },
            parService: parService
        )

        do {
            _ = try await service.authorizeUser(
                requestData: makeValidRequestData(
                    pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par",
                    requirePushedAuthorizationRequests: true
                )
            )
            XCTFail("Expected PushedAuthorizationRequestException to be thrown")
        } catch is PushedAuthorizationRequestException {
            XCTAssertFalse(callbackInvoked, "Must not fall back when PAR is mandatory")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func test_authorizeUser_whenParIsMandatoryButNoEndpointAdvertised_throws() async {
        let parService = StubPARService(
            result: .success(
                PushedAuthorizationResponse(requestUri: "urn:req:abc", expiresIn: 90)
            )
        )
        var callbackInvoked = false
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { _ in
                callbackInvoked = true
                return ["code": "authcode123"]
            },
            parService: parService
        )

        do {
            _ = try await service.authorizeUser(
                requestData: makeValidRequestData(requirePushedAuthorizationRequests: true)
            )
            XCTFail("Expected PushedAuthorizationRequestException to be thrown")
        } catch is PushedAuthorizationRequestException {
            XCTAssertEqual(parService.callCount, 0)
            XCTAssertFalse(callbackInvoked)
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func test_authorizeUser_whenParIsOptionalAndParFails_fallsBackToStandardRequest() async throws {
        let parService = StubPARService(
            result: .failure(PushedAuthorizationRequestException(message: "HTTP 400"))
        )
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(
            requestData: makeValidRequestData(
                pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par",
                requirePushedAuthorizationRequests: false
            )
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 1)
        XCTAssertFalse(capturedUrl?.contains("request_uri") ?? true)
        XCTAssertTrue(capturedUrl?.contains("code_challenge=challenge-xyz") ?? false)
    }

    func test_authorizeUser_whenParFlagOmittedAndParFails_fallsBackToStandardRequest() async throws {
        let parService = StubPARService(
            result: .failure(PushedAuthorizationRequestException(message: "timeout"))
        )
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(
            requestData: makeValidRequestData(
                pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par"
            )
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 1)
        XCTAssertFalse(capturedUrl?.contains("request_uri") ?? true)
    }

    func test_authorizeUser_whenParIsExplicitlyOptionalAndParSucceeds_usesPushedRequest() async throws {
        let parService = StubPARService(
            result: .success(
                PushedAuthorizationResponse(requestUri: "urn:req:abc", expiresIn: 90)
            )
        )
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(
            requestData: makeValidRequestData(
                pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par",
                requirePushedAuthorizationRequests: false
            )
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 1)
        XCTAssertTrue(capturedUrl?.contains("request_uri=urn:req:abc") ?? false)
    }

    func test_authorizeUser_whenParIsExplicitlyOptionalAndNoEndpoint_usesStandardRequest() async throws {
        let parService = StubPARService(
            result: .success(
                PushedAuthorizationResponse(requestUri: "urn:req:abc", expiresIn: 90)
            )
        )
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(
            requestData: makeValidRequestData(requirePushedAuthorizationRequests: false)
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 0)
        XCTAssertFalse(capturedUrl?.contains("request_uri") ?? true)
    }

    func test_authorizeUser_whenOptionalParFailsWithOtherError_fallsBackToStandardRequest() async throws {
        let parService = StubPARService(result: .failure(StubPARError.unexpected))
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(
            requestData: makeValidRequestData(
                pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par",
                requirePushedAuthorizationRequests: false
            )
        )

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 1)
        XCTAssertFalse(capturedUrl?.contains("request_uri") ?? true)
    }

    func test_authorizeUser_whenMandatoryParFailsWithOtherError_throwsWithoutFallback() async {
        let parService = StubPARService(result: .failure(StubPARError.unexpected))
        var callbackInvoked = false
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { _ in
                callbackInvoked = true
                return ["code": "authcode123"]
            },
            parService: parService
        )

        do {
            _ = try await service.authorizeUser(
                requestData: makeValidRequestData(
                    pushedAuthorizationRequestEndpoint: "https://as.example.com/as/par",
                    requirePushedAuthorizationRequests: true
                )
            )
            XCTFail("Expected the PAR failure to propagate")
        } catch {
            XCTAssertFalse(callbackInvoked, "Must not fall back when PAR is mandatory")
        }
    }

    func test_authorizeUser_whenParFlagOmittedAndNoEndpoint_usesStandardRequestWithoutPar() async throws {
        let parService = StubPARService(
            result: .success(
                PushedAuthorizationResponse(requestUri: "urn:req:abc", expiresIn: 90)
            )
        )
        var capturedUrl: String?
        let service = RedirectToWebAuthorizationMethodService(
            openWebPage: { url in
                capturedUrl = url
                return ["code": "authcode123"]
            },
            parService: parService
        )

        let response = try await service.authorizeUser(requestData: makeValidRequestData())

        XCTAssertEqual(response.status, "success")
        XCTAssertEqual(parService.callCount, 0)
        XCTAssertFalse(capturedUrl?.contains("request_uri") ?? true)
    }
}

// Dummy class to simulate invalid request data
private final class DummyAuthorizationRequestData: AuthorizationRequestData {}

private enum StubPARError: Error {
    case unexpected
}

private final class StubPARService: PushedAuthorizationRequestService {
    private let result: Result<PushedAuthorizationResponse, Error>
    private(set) var callCount = 0

    init(result: Result<PushedAuthorizationResponse, Error>) {
        self.result = result
        super.init()
    }

    override func pushAuthorizationRequest(
        parEndpoint: String,
        clientId: String,
        redirectUri: String,
        codeChallenge: String,
        state: String,
        nonce: String,
        scope: String? = nil,
        dpopJkt: String? = nil,
        codeChallengeMethod: CodeChallengeMethod = .s256,
        responseType: AuthorizationResponseType = .code,
        clientAuthParams: [String: String] = [:],
        timeoutMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        session: NetworkManager = NetworkManager.shared
    ) async throws -> PushedAuthorizationResponse {
        callCount += 1
        switch result {
        case .success(let response):
            return response
        case .failure(let error):
            throw error
        }
    }
}
