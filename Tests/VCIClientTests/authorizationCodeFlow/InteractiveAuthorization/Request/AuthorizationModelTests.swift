import XCTest
@testable import VCIClient

//TODO: separate test files
final class AuthorizationModelTests: XCTestCase {

    // MARK: - AuthorizationDetail

    func test_AuthorizationDetail_encodeDecode_withClaims() throws {
        let detail = AuthorizationDetails(
            type: "openid_credential",
            credentialConfigurationId: "credConfig1",
            claims: ["given_name": "true", "family_name": "true"]
        )

        let data = try JSONEncoder().encode(detail)
        // Ensure keys are mapped as expected
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["type"] as? String, "openid_credential")
        XCTAssertEqual(json["credential_configuration_id"] as? String, "credConfig1")
        let claims = json["claims"] as? [String: String]
        XCTAssertEqual(claims?["given_name"], "true")
        XCTAssertEqual(claims?["family_name"], "true")

        // Round-trip
        let decoded = try JSONDecoder().decode(AuthorizationDetails.self, from: data)
        XCTAssertEqual(decoded.type, "openid_credential")
        XCTAssertEqual(decoded.credentialConfigurationId, "credConfig1")
        XCTAssertEqual(decoded.claims?["given_name"], "true")
        XCTAssertEqual(decoded.claims?["family_name"], "true")
    }

    func test_AuthorizationDetail_encodeDecode_withoutClaims() throws {
        let detail = AuthorizationDetails(
            type: "openid_credential",
            credentialConfigurationId: "credConfig1"
        )

        let data = try JSONEncoder().encode(detail)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["type"] as? String, "openid_credential")
        XCTAssertEqual(json["credential_configuration_id"] as? String, "credConfig1")
        XCTAssertNil(json["claims"], "claims should be omitted when nil")

        let decoded = try JSONDecoder().decode(AuthorizationDetails.self, from: data)
        XCTAssertEqual(decoded.type, "openid_credential")
        XCTAssertEqual(decoded.credentialConfigurationId, "credConfig1")
        XCTAssertNil(decoded.claims)
    }

    // MARK: - IARInitialRequestBody

    func test_IARInitialRequestBody_defaults_and_toFormMap() throws {
        let details = [
            AuthorizationDetails(type: "openid_credential", credentialConfigurationId: "cfg1")
        ]
        let body = IARInitialRequestBody(
            clientId: "client-123",
            codeChallenge: "abc123",
            redirectUri: "app://callback",
            authorizationDetails: details,
            interactionTypesSupported: ["openid4vp_presentation", "something_else"],
            dpopJkt: "test-jkt"
        )

        // Verify defaulted fields
        XCTAssertEqual(body.responseType, "code")
        XCTAssertEqual(body.codeChallengeMethod, "S256")

        // Verify CodingKeys by encoding to JSON
        let data = try JSONEncoder().encode(body)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["response_type"] as? String, "code")
        XCTAssertEqual(json["client_id"] as? String, "client-123")
        XCTAssertEqual(json["code_challenge"] as? String, "abc123")
        XCTAssertEqual(json["code_challenge_method"] as? String, "S256")
        XCTAssertEqual(json["redirect_uri"] as? String, "app://callback")
        XCTAssertEqual(json["interaction_types_supported"] as? String, "openid4vp_presentation,something_else")

        // authorization_details should be an array of objects
        let authDetailsJson = try XCTUnwrap(json["authorization_details"] as? [[String: Any]])
        XCTAssertEqual(authDetailsJson.count, 1)
        XCTAssertEqual(authDetailsJson.first?["type"] as? String, "openid_credential")
        XCTAssertEqual(authDetailsJson.first?["credential_configuration_id"] as? String, "cfg1")

        // Verify toFormMap output
        let form = body.toFormMap()
        XCTAssertEqual(form["response_type"], "code")
        XCTAssertEqual(form["client_id"], "client-123")
        XCTAssertEqual(form["code_challenge"], "abc123")
        XCTAssertEqual(form["code_challenge_method"], "S256")
        XCTAssertEqual(form["redirect_uri"], "app://callback")

        // interaction_types_supported CSV
        XCTAssertEqual(form["interaction_types_supported"], "openid4vp_presentation,something_else")

        // authorization_details should be JSON string of the array
        let authDetailsString = try XCTUnwrap(form["authorization_details"])
        let authDetailsData = try XCTUnwrap(authDetailsString.data(using: .utf8))
        let authDetailsParsed = try JSONSerialization.jsonObject(with: authDetailsData) as? [[String: Any]]
        XCTAssertEqual(authDetailsParsed?.count, 1)
        XCTAssertEqual(authDetailsParsed?.first?["type"] as? String, "openid_credential")
        XCTAssertEqual(authDetailsParsed?.first?["credential_configuration_id"] as? String, "cfg1")
    }


    func test_IARInitialRequestBody_toFormMap_includesLegacyAndIAEInteractionTypes() throws {

        let details = [
            AuthorizationDetails(
                type: "openid_credential",
                credentialConfigurationId: "cfg1"
            )
        ]

        let body = IARInitialRequestBody(
            clientId: "client-123",
            codeChallenge: "challenge",
            redirectUri: "app://callback",
            authorizationDetails: details,
            interactionTypesSupported: [
                InteractionType.openId4VpPresentation.rawValue,
                InteractionType.openId4VpPresentationIAE.rawValue
            ],
            dpopJkt: "test-jkt"
        )

        let form = body.toFormMap()

        XCTAssertEqual(
            form["interaction_types_supported"],
            "\(InteractionType.openId4VpPresentation.rawValue),\(InteractionType.openId4VpPresentationIAE.rawValue)"
        )
    }

    func test_IARInitialRequestBody_includesDpopJkt_whenProvided() throws {
        let body = IARInitialRequestBody(
            clientId: "client-123",
            codeChallenge: "challenge",
            redirectUri: "app://callback",
            authorizationDetails: [],
            interactionTypesSupported: ["openid4vp_presentation"],
            dpopJkt: "thumb-print-value"
        )

        XCTAssertEqual(body.toFormMap()["dpop_jkt"], "thumb-print-value")

        let data = try JSONEncoder().encode(body)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["dpop_jkt"] as? String, "thumb-print-value")
    }

    // MARK: - AuthorizationResponse (Codable)

    func test_AuthorizationResponse_success_decode_encode() throws {
        // Simulate a success JSON from issuer
        let json: [String: Any] = [
            "code": "code-xyz",
            "status": "success",
            "auth_session": "sess-1"
        ]
        let data = try JSONSerialization.data(withJSONObject: json)
        let decoded = try JSONDecoder().decode(AuthorizationResponse.self, from: data)

        XCTAssertEqual(decoded.authorizationCode, "code-xyz")
        XCTAssertEqual(decoded.status, "success")
        XCTAssertNil(decoded.error)
        XCTAssertNil(decoded.errorDescription)
        XCTAssertEqual(decoded.authSession, "sess-1")

        // Round-trip encode
        let encoded = try JSONEncoder().encode(decoded)
        let roundTrip = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        XCTAssertEqual(roundTrip?["code"] as? String, "code-xyz")
        XCTAssertEqual(roundTrip?["status"] as? String, "success")
        XCTAssertEqual(roundTrip?["auth_session"] as? String, "sess-1")
        XCTAssertNil(roundTrip?["error"])
        XCTAssertNil(roundTrip?["error_description"])
    }

    func test_AuthorizationResponse_error_decode_encode() throws {
        // Simulate an error JSON from issuer
        let json: [String: Any] = [
            "status": "error",
            "error": "invalid_request",
            "error_description": "bad stuff",
            "auth_session": "sess-2"
        ]
        let data = try JSONSerialization.data(withJSONObject: json)
        let decoded = try JSONDecoder().decode(AuthorizationResponse.self, from: data)

        XCTAssertNil(decoded.authorizationCode)
        XCTAssertEqual(decoded.status, "error")
        XCTAssertEqual(decoded.error, "invalid_request")
        XCTAssertEqual(decoded.errorDescription, "bad stuff")
        XCTAssertEqual(decoded.authSession, "sess-2")

        // Round-trip encode
        let encoded = try JSONEncoder().encode(decoded)
        let roundTrip = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        XCTAssertEqual(roundTrip?["status"] as? String, "error")
        XCTAssertEqual(roundTrip?["error"] as? String, "invalid_request")
        XCTAssertEqual(roundTrip?["error_description"] as? String, "bad stuff")
        XCTAssertEqual(roundTrip?["auth_session"] as? String, "sess-2")
        XCTAssertNil(roundTrip?["code"])
    }

    // MARK: - AuthorizationRequestData

    func test_AuthorizationRequestData_conformance_with_PresentationDuringIssuanceRequestData() throws {
        // Since AuthorizationRequestData is an empty protocol, verify conformance via a concrete type
        let payload: [String: Any] = ["response_type": "vp_token", "response_mode": "iar-post"]
        let req = PresentationDuringIssuanceRequestData(
            ovpRequest: payload,
            authSession: "auth-session-123",
            iar: "https://issuer.example.com/iar"
        )

        // Compile-time conformance check
        func assertConformance<T: AuthorizationRequestData>(_ value: T) -> T { value }
        let same = assertConformance(req)

        // Verify stored properties
        XCTAssertEqual(same.authSession, "auth-session-123")
        XCTAssertEqual(same.iar, "https://issuer.example.com/iar")
        XCTAssertEqual(same.ovpRequest["response_type"] as? String, "vp_token")
        XCTAssertEqual(same.ovpRequest["response_mode"] as? String, "iar-post")
    }
}
