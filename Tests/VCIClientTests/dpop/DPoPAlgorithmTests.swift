@testable import VCIClient
import XCTest

final class DPoPAlgorithmTests: XCTestCase {
    func test_defaultsToEs256WhenNilOrEmpty() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(nil), .es256)
        XCTAssertEqual(try DPoPAlgorithm.select([]), .es256)
    }

    // Priority group 1 – ed (EdDSA)
    func test_prefersEdDSAOverAllOtherAlgorithms() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(["RS256", "ES256", "ES256K", "EdDSA"]), .eddsa)
    }

    // Priority group 2 – eck1 (ES256K / secp256k1)
    func test_prefersEs256kOverEcr1VariantsAndRsa() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(["ES512", "ES256K", "ES256"]), .es256k)
    }

    // Priority group 3 – ecr1 (ES256 / secp256r1)
    func test_prefersEs256OverLargerEcCurvesAndRsa() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(["ES512", "ES384", "ES256"]), .es256)
    }

    // Priority group 4 – other EC r1 variants (ES384 before ES512)
    func test_prefersEs384OverEs512AndRsa() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(["RS256", "ES512", "ES384"]), .es384)
    }

    func test_prefersEs512OverRsa() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(["RS256", "ES512"]), .es512)
    }

    // Priority group 5 – rsa (RS256); last resort
    func test_selectsRs256WhenOnlyRecognisedAlgorithm() throws {
        XCTAssertEqual(try DPoPAlgorithm.select(["RS256", "PS512"]), .rs256)
    }

    func test_throwsWhenOnlyUnsupportedAlgorithmsAdvertised() {
        XCTAssertThrowsError(try DPoPAlgorithm.select(["PS256", "HS256"])) { error in
            let vcierror = error as? VCIClientException
            XCTAssertEqual(vcierror?.code, "VCI-013")
            XCTAssertTrue(vcierror?.message.contains("No supported DPoP algorithm found") ?? false)
        }
    }
}
