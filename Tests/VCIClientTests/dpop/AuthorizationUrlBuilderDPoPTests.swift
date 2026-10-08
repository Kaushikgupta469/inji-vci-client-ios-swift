@testable import VCIClient
import XCTest

final class AuthorizationUrlBuilderDPoPTests: XCTestCase {
    func test_appendsDpopJktWhenProvided() {
        let url = AuthorizationUrlBuilder.buildWithParameters(
            baseUrl: "https://example.com/auth",
            clientId: "client",
            redirectUri: "https://app/callback",
            scope: "openid",
            state: "state",
            codeChallenge: "challenge",
            nonce: "nonce",
            dpopJkt: "thumb-print-value"
        )
        XCTAssertTrue(url.hasSuffix("&dpop_jkt=thumb-print-value"))
    }
}
