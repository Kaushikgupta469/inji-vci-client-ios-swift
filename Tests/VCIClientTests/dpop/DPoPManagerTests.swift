@testable import VCIClient
import CryptoKit
import XCTest

final class DPoPManagerTests: XCTestCase {

    private func initializedManager(
        tokenEndpoint: String = "https://as.example.com/token",
        algorithms: [String]? = ["ES256"]
    ) throws -> DPoPManager {
        let manager = DPoPManager()
        try manager.initialize(tokenEndpoint: tokenEndpoint, authorizationServerSupportedAlgorithms: algorithms)
        return manager
    }

    private func segment(_ value: String) throws -> [String: Any] {
        let data = try XCTUnwrap(try Data(base64URLEncodedString: value))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func test_isInitialized() throws {
        XCTAssertFalse(DPoPManager().isInitialized)
        XCTAssertTrue(try initializedManager().isInitialized)
    }

    func test_tokenProof_headerAndClaims() throws {
        let proof = try initializedManager().generateTokenProof()
        let parts = proof.components(separatedBy: ".")
        XCTAssertEqual(parts.count, 3)

        let header = try segment(parts[0])
        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(header["alg"] as? String, "ES256")
        let jwk = try XCTUnwrap(header["jwk"] as? [String: String])
        XCTAssertEqual(jwk["kty"], "EC")
        XCTAssertEqual(jwk["crv"], "P-256")
        XCTAssertNotNil(jwk["x"])
        XCTAssertNotNil(jwk["y"])
        XCTAssertNil(jwk["d"])

        let claims = try segment(parts[1])
        XCTAssertNotNil(claims["jti"])
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertEqual(claims["htu"] as? String, "https://as.example.com/token")
        XCTAssertNotNil(claims["iat"])
        XCTAssertNotNil(claims["exp"])
        XCTAssertNil(claims["ath"])
        XCTAssertNil(claims["nonce"])
    }

    func test_tokenProof_isVerifiableWithEmbeddedPublicKey() throws {
        let proof = try initializedManager().generateTokenProof()
        let parts = proof.components(separatedBy: ".")
        let header = try segment(parts[0])
        let jwk = try XCTUnwrap(header["jwk"] as? [String: String])

        let x = try XCTUnwrap(try Data(base64URLEncodedString: try XCTUnwrap(jwk["x"])))
        let y = try XCTUnwrap(try Data(base64URLEncodedString: try XCTUnwrap(jwk["y"])))
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: x + y)

        let signatureData = try XCTUnwrap(try Data(base64URLEncodedString: parts[2]))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)

        XCTAssertTrue(publicKey.isValidSignature(signature, for: signingInput))
    }

    func test_producesProofForEverySupportedAlgorithm() throws {
        let algorithms = ["EdDSA", "ES256K", "ES256", "ES384", "ES512", "RS256"]
        for alg in algorithms {
            let manager = try initializedManager(algorithms: [alg])
            let parts = try manager.generateTokenProof().components(separatedBy: ".")
            XCTAssertEqual(parts.count, 3, "proof for \(alg) must be a compact JWS")

            let header = try segment(parts[0])
            XCTAssertEqual(header["alg"] as? String, alg)
            XCTAssertEqual(header["typ"] as? String, "dpop+jwt")

            let jwk = try XCTUnwrap(header["jwk"] as? [String: Any])
            XCTAssertNil(jwk["d"], "public JWK for \(alg) must not contain private key 'd'")
            XCTAssertNil(jwk["p"], "public JWK for \(alg) must not contain private key 'p'")
            XCTAssertNil(jwk["q"], "public JWK for \(alg) must not contain private key 'q'")

            XCTAssertFalse(try manager.jwkThumbprint().isEmpty)
        }
    }

    // Guards against CryptoSwift#892: RS256 key construction used to fail on ~half of random keys.
    func test_rs256ProofGenerationIsReliableAcrossManyKeys() throws {
        for _ in 0..<15 {
            let manager = try initializedManager(algorithms: ["RS256"])
            let parts = try manager.generateTokenProof().components(separatedBy: ".")
            XCTAssertEqual(parts.count, 3)
            XCTAssertEqual(try segment(parts[0])["alg"] as? String, "RS256")
            XCTAssertFalse(try manager.jwkThumbprint().isEmpty)
        }
    }

    func test_tokenProof_includesNonceWhenSupplied() throws {
        let manager = try initializedManager()
        let claims = try segment(try manager.generateTokenProof(nonce: "nonce-123").components(separatedBy: ".")[1])
        XCTAssertEqual(claims["nonce"] as? String, "nonce-123")
    }

    func test_credentialProof_usesStoredIssuerNonceWhenNoneSupplied() throws {
        let manager = try initializedManager()
        manager.updateNonce("issuer-nonce")
        let proof = try manager.generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: "an-access-token"
        )
        let claims = try segment(proof.components(separatedBy: ".")[1])
        XCTAssertEqual(claims["nonce"] as? String, "issuer-nonce")
    }

    func test_credentialProof_suppliedNonceOverridesAndUpdatesStoredNonce() throws {
        let manager = try initializedManager()
        manager.updateNonce("old-nonce")

        let first = try segment(try manager.generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: "an-access-token",
            nonce: "new-nonce"
        ).components(separatedBy: ".")[1])
        XCTAssertEqual(first["nonce"] as? String, "new-nonce")

        let second = try segment(try manager.generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: "an-access-token"
        ).components(separatedBy: ".")[1])
        XCTAssertEqual(second["nonce"] as? String, "new-nonce")
    }

    func test_updateNonce_ignoresBlankValues() throws {
        let manager = try initializedManager()
        manager.updateNonce("issuer-nonce")
        manager.updateNonce(nil)
        manager.updateNonce(" ")
        let claims = try segment(try manager.generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: "an-access-token"
        ).components(separatedBy: ".")[1])
        XCTAssertEqual(claims["nonce"] as? String, "issuer-nonce")
    }

    func test_resetClearsStoredIssuerNonce() throws {
        let manager = try initializedManager()
        manager.updateNonce("issuer-nonce")
        manager.reset()
        try manager.initialize(tokenEndpoint: "https://as.example.com/token", authorizationServerSupportedAlgorithms: ["ES256"])
        let claims = try segment(try manager.generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: "an-access-token"
        ).components(separatedBy: ".")[1])
        XCTAssertNil(claims["nonce"] as? String)
    }

    func test_credentialProof_includesAth() throws {
        let accessToken = "an-access-token"
        let proof = try initializedManager().generateCredentialProof(
            credentialEndpoint: "https://issuer.example.com/credential",
            accessToken: accessToken
        )
        let claims = try segment(proof.components(separatedBy: ".")[1])

        let expectedAth = Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLEncodedString()
        XCTAssertEqual(claims["ath"] as? String, expectedAth)
        XCTAssertEqual(claims["htu"] as? String, "https://issuer.example.com/credential")
    }

    func test_htuStripsQueryAndFragment() throws {
        let manager = DPoPManager()
        try manager.initialize(tokenEndpoint: "https://as.example.com/token?foo=bar#frag", authorizationServerSupportedAlgorithms: ["ES256"])
        let claims = try segment(try manager.generateTokenProof().components(separatedBy: ".")[1])
        XCTAssertEqual(claims["htu"] as? String, "https://as.example.com/token")
    }

    func test_htuCanonicalizesSchemeHostDefaultPortAndEmptyPath() throws {
        let manager = DPoPManager()
        try manager.initialize(tokenEndpoint: "HTTPS://AS.EXAMPLE.COM:443?foo=bar", authorizationServerSupportedAlgorithms: ["ES256"])
        let tokenClaims = try segment(try manager.generateTokenProof().components(separatedBy: ".")[1])
        XCTAssertEqual(tokenClaims["htu"] as? String, "https://as.example.com/")

        let credentialProof = try manager.generateCredentialProof(
            credentialEndpoint: "HTTP://ISSUER.EXAMPLE.COM:80/credential?x=1#fragment",
            accessToken: "access-token"
        )
        let credentialClaims = try segment(credentialProof.components(separatedBy: ".")[1])
        XCTAssertEqual(credentialClaims["htu"] as? String, "http://issuer.example.com/credential")
    }

    func test_thumbprintMatchesEmbeddedJwk() throws {
        let manager = try initializedManager()
        let header = try segment(try manager.generateTokenProof().components(separatedBy: ".")[0])
        let jwk = try XCTUnwrap(header["jwk"] as? [String: String])

        let canonical = try JSONSerialization.data(
            withJSONObject: ["crv": jwk["crv"]!, "kty": "EC", "x": jwk["x"]!, "y": jwk["y"]!],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let expected = Data(SHA256.hash(data: canonical)).base64URLEncodedString()
        XCTAssertEqual(try manager.jwkThumbprint(), expected)
    }

    func test_eachProofHasUniqueJti() throws {
        let manager = try initializedManager()
        let first = try segment(try manager.generateTokenProof().components(separatedBy: ".")[1])["jti"] as? String
        let second = try segment(try manager.generateTokenProof().components(separatedBy: ".")[1])["jti"] as? String
        XCTAssertNotEqual(first, second)
    }

    func test_selectsAdvertisedCurve() throws {
        let header = try segment(try initializedManager(algorithms: ["ES384"]).generateTokenProof().components(separatedBy: ".")[0])
        XCTAssertEqual(header["alg"] as? String, "ES384")
    }

    func test_fallsBackToEs256WhenListAbsent() throws {
        let header = try segment(try initializedManager(algorithms: nil).generateTokenProof().components(separatedBy: ".")[0])
        XCTAssertEqual(header["alg"] as? String, "ES256")
    }

    func test_generateProofThrowsWhenNotInitialized() {
        XCTAssertThrowsError(try DPoPManager().generateTokenProof()) { error in
            XCTAssertEqual((error as? VCIClientException)?.code, "VCI-013")
        }
    }

    func test_jwkThumbprintThrowsWhenNotInitialized() {
        XCTAssertThrowsError(try DPoPManager().jwkThumbprint()) { error in
            XCTAssertEqual((error as? VCIClientException)?.code, "VCI-013")
        }
    }

    func test_resetClearsSession() throws {
        let manager = try initializedManager()
        manager.reset()
        XCTAssertFalse(manager.isInitialized)
    }

    func test_initializeIsIdempotent() throws {
        let manager = try initializedManager()
        let before = try manager.jwkThumbprint()
        try manager.initialize(tokenEndpoint: "https://other.example.com/token", authorizationServerSupportedAlgorithms: ["ES384"])
        XCTAssertEqual(try manager.jwkThumbprint(), before)
    }
}
