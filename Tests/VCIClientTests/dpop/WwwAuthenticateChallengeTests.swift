@testable import VCIClient
import XCTest

final class WwwAuthenticateChallengeTests: XCTestCase {
    func test_parsesDpopUseDpopNonceChallenge() {
        let challenge = WwwAuthenticateChallenge.parse(#"DPoP error="use_dpop_nonce", error_description="nonce required""#)
        XCTAssertTrue(challenge.isDpop)
        XCTAssertFalse(challenge.isBearer)
        XCTAssertEqual(challenge.error, "use_dpop_nonce")
    }

    func test_parsesBearerOnlyChallenge() {
        let challenge = WwwAuthenticateChallenge.parse(#"Bearer realm="issuer", error="invalid_token""#)
        XCTAssertFalse(challenge.isDpop)
        XCTAssertTrue(challenge.isBearer)
        XCTAssertEqual(challenge.error, "invalid_token")
    }

    func test_detectsDpopAmongMultipleSchemes() {
        let challenge = WwwAuthenticateChallenge.parse(#"Bearer realm="r", DPoP algs="ES256""#)
        XCTAssertTrue(challenge.isDpop)
        XCTAssertTrue(challenge.isBearer)
    }

    func test_detectsCommaAdjacentDpopScheme() {
        // DPoP immediately followed by a comma (no trailing whitespace) must still be detected.
        let challenge = WwwAuthenticateChallenge.parse(#"DPoP, Bearer realm="issuer""#)
        XCTAssertTrue(challenge.isDpop)
        XCTAssertTrue(challenge.isBearer)
    }

    func test_detectsSchemesWithNoSpaceAfterComma() {
        let challenge = WwwAuthenticateChallenge.parse("Bearer,DPoP")
        XCTAssertTrue(challenge.isDpop)
        XCTAssertTrue(challenge.isBearer)
    }

    func test_emptyForNilOrBlank() {
        for value in [nil, "", "   "] {
            let challenge = WwwAuthenticateChallenge.parse(value)
            XCTAssertFalse(challenge.isDpop)
            XCTAssertFalse(challenge.isBearer)
            XCTAssertNil(challenge.error)
        }
    }

    func test_isBearerFalseForUnrecognisedScheme() {
        let challenge = WwwAuthenticateChallenge.parse(#"NTLM realm="corp""#)
        XCTAssertFalse(challenge.isDpop)
        XCTAssertFalse(challenge.isBearer)
    }
}
