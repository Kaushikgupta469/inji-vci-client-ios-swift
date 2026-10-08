@testable import VCIClient
import XCTest

final class PresentationInteractionResponseTests: XCTestCase {
    func testInitFromJson_requiresOpenId4VpRequest() {
        XCTAssertThrowsError(
            try PresentationInteractionResponse(
                json: [
                    "status": "require_interaction",
                    "type": "openid4vp_presentation",
                    "auth_session": "session-1",
                ]
            )
        ) { error in
            XCTAssertTrue(error is IllegalArgumentException)
        }
    }

    func testDecoding_acceptsNestedDictionaryRequest() throws {
        let data = """
        {
            "status": "require_interaction",
            "type": "openid4vp_presentation",
            "auth_session": "session-1",
            "openid4vp_request": {
                "response_type": "vp_token",
                "response_mode": "iar-post",
                "presentation_definition": {
                    "id": "pd-1"
                }
            }
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(
            PresentationInteractionResponse.self,
            from: data
        )

        XCTAssertEqual(response.status, "require_interaction")
        XCTAssertEqual(response.authSession, "session-1")
        XCTAssertEqual(response.openid4vpRequest["response_type"] as? String, "vp_token")
        XCTAssertEqual(
            (response.openid4vpRequest["presentation_definition"] as? [String: Any])?["id"] as? String,
            "pd-1"
        )
    }

    func testValidate_acceptsUnsignedRequestForLibraryValidation() throws {
        let response = try PresentationInteractionResponse(
            json: [
                "status": "require_interaction",
                "type": "openid4vp_presentation",
                "auth_session": "session-1",
                "openid4vp_request": [
                    "response_type": "vp_token"
                ],
            ]
        )

        XCTAssertNoThrow(try response.validate())
    }

    func testValidate_acceptsSignedRequestForLibraryValidation() throws {
        let response = try PresentationInteractionResponse(
            json: [
                "status": "require_interaction",
                "type": "openid4vp_presentation",
                "auth_session": "session-1",
                "openid4vp_request": [
                    "request": "signed-request-jwt",
                ],
            ]
        )

        XCTAssertNoThrow(try response.validate())
    }

    func testValidate_acceptsRequestUriForLibraryValidation() throws {
        let response = try PresentationInteractionResponse(
            json: [
                "status": "require_interaction",
                "type": "openid4vp_presentation",
                "auth_session": "session-1",
                "openid4vp_request": [
                    "request_uri": "https://verifier.example.com/request/123",
                ],
            ]
        )

        XCTAssertNoThrow(try response.validate())
    }

    func testValidate_rejectsInvalidType() throws {
        let response = try PresentationInteractionResponse(
            json: [
                "status": "require_interaction",
                "type": "wrong_type",
                "auth_session": "session-1",
                "openid4vp_request": [
                    "response_type": "vp_token",
                    "response_mode": "iar-post",
                ],
            ]
        )

        XCTAssertThrowsError(try response.validate()) { error in
            XCTAssertTrue(error is IllegalArgumentException)
        }
    }

    func testValidate_rejectsEmptyRequest() throws {
        let response = try PresentationInteractionResponse(
            json: [
                "status": "require_interaction",
                "type": "openid4vp_presentation",
                "auth_session": "session-1",
                "openid4vp_request": [:],
            ]
        )

        XCTAssertThrowsError(try response.validate())
    }

    func testValidate_acceptsDcpInteractionType() throws {
        let response = try PresentationInteractionResponse(
            json: [
                "status": "require_interaction",
                "type": "urn:openid:dcp:iae:openid4vp_presentation",
                "auth_session": "session-1",
                "openid4vp_request": [
                    "response_type": "vp_token"
                ]
            ]
        )

        XCTAssertNoThrow(try response.validate())
    }
}
