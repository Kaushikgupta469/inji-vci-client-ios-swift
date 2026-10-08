@testable import VCIClient
import XCTest

final class WellKnownUrlTests: XCTestCase {

    func test_insertsSuffixBetweenAuthorityAndPathPerRFC8414() {
        XCTAssertEqual(
            WellKnownUrl.insertSuffix(
                baseUrl: "https://host.example.com/v1/issuer",
                suffix: "/.well-known/openid-credential-issuer"
            ),
            "https://host.example.com/.well-known/openid-credential-issuer/v1/issuer"
        )
    }

    func test_appendsSuffixWhenThereIsNoPath() {
        XCTAssertEqual(
            WellKnownUrl.insertSuffix(
                baseUrl: "https://host.example.com",
                suffix: "/.well-known/oauth-authorization-server"
            ),
            "https://host.example.com/.well-known/oauth-authorization-server"
        )
    }

    func test_preservesPortAndTrimsTrailingPathSlash() {
        XCTAssertEqual(
            WellKnownUrl.insertSuffix(
                baseUrl: "https://host.example.com:8443/tenant/",
                suffix: "/.well-known/openid-configuration"
            ),
            "https://host.example.com:8443/.well-known/openid-configuration/tenant"
        )
    }

    func test_returnsNilForInvalidUrl() {
        XCTAssertNil(WellKnownUrl.insertSuffix(baseUrl: "not a url", suffix: "/.well-known/x"))
    }

    func test_preservesPercentEncodedPathSegments() {
        XCTAssertEqual(
            WellKnownUrl.insertSuffix(
                baseUrl: "https://host.example.com/tenant%2Falpha",
                suffix: "/.well-known/openid-configuration"
            ),
            "https://host.example.com/.well-known/openid-configuration/tenant%2Falpha"
        )
    }

    func test_buildCandidateWellKnownUrls_insertsForPathBasedIssuer() {
        let candidates = AuthorizationServerDiscoveryService.buildCandidateWellKnownUrls(
            baseUrl: "https://host.example.com/v1/esignet"
        )
        XCTAssertEqual(
            candidates,
            [
                "https://host.example.com/.well-known/oauth-authorization-server/v1/esignet",
                "https://host.example.com/.well-known/openid-configuration/v1/esignet",
                "https://host.example.com/v1/esignet/.well-known/oauth-authorization-server",
                "https://host.example.com/v1/esignet/.well-known/openid-configuration"
            ]
        )
    }

    func test_buildCandidateWellKnownUrls_onlyAppendsForPathlessIssuer() {
        let candidates = AuthorizationServerDiscoveryService.buildCandidateWellKnownUrls(
            baseUrl: "https://host.example.com"
        )
        XCTAssertEqual(
            candidates,
            [
                "https://host.example.com/.well-known/oauth-authorization-server",
                "https://host.example.com/.well-known/openid-configuration"
            ]
        )
    }
}
