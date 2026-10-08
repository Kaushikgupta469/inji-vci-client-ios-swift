@testable import VCIClient
import XCTest

final class AuthorizationServerMetadataTests: XCTestCase {

    func test_decodesRequireParFlagWhenAdvertisedAsTrue() throws {
        let json = """
        {"issuer":"https://as.example","require_pushed_authorization_requests":true}
        """

        let metadata = try JsonUtils.deserialize(json, as: AuthorizationServerMetadata.self)

        XCTAssertEqual(metadata?.requirePushedAuthorizationRequests, true)
    }

    func test_decodesRequireParFlagWhenAdvertisedAsFalse() throws {
        let json = """
        {"issuer":"https://as.example","require_pushed_authorization_requests":false}
        """

        let metadata = try JsonUtils.deserialize(json, as: AuthorizationServerMetadata.self)

        XCTAssertEqual(metadata?.requirePushedAuthorizationRequests, false)
    }

    func test_leavesRequireParFlagNilWhenOmitted() throws {
        let json = """
        {
          "issuer":"https://as.example",
          "pushed_authorization_request_endpoint":"https://as.example/as/par"
        }
        """

        let metadata = try JsonUtils.deserialize(json, as: AuthorizationServerMetadata.self)

        XCTAssertNil(metadata?.requirePushedAuthorizationRequests)
        XCTAssertEqual(
            metadata?.pushedAuthorizationRequestEndpoint,
            "https://as.example/as/par"
        )
        XCTAssertEqual(metadata?.requirePushedAuthorizationRequests ?? false, false)
    }
}
