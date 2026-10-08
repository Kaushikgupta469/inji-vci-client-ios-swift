import XCTest
@testable import VCIClient

final class IssuerMetadataResultTests: XCTestCase {
    private let credentialConfigurationId = "UniversityDegreeCredential"

    private func result(with credentialConfiguration: [String: Any]) -> IssuerMetadataResult {
        IssuerMetadataResult(
            issuerMetadata: mockIssuerMetadata(),
            raw: [
                "credential_configurations_supported": [
                    credentialConfigurationId: credentialConfiguration
                ]
            ]
        )
    }

    func testExtractsJwtProofSigningAlgorithms() {
        let metadata = result(with: [
            "proof_types_supported": [
                "jwt": ["proof_signing_alg_values_supported": ["ES256", "RS256"]]
            ]
        ])

        XCTAssertEqual(
            metadata.extractJwtProofSigningAlgorithms(credentialConfigurationId: credentialConfigurationId),
            ["ES256", "RS256"]
        )
    }

    func testDropsNonStringSigningAlgorithms() {
        let metadata = result(with: [
            "proof_types_supported": [
                "jwt": ["proof_signing_alg_values_supported": ["ES256", 42, "RS256"]]
            ]
        ])

        XCTAssertEqual(
            metadata.extractJwtProofSigningAlgorithms(credentialConfigurationId: credentialConfigurationId),
            ["ES256", "RS256"]
        )
    }

    func testExtractsEveryAdvertisedProofType() {
        let metadata = result(with: [
            "proof_types_supported": [
                "jwt": ["proof_signing_alg_values_supported": ["ES256"]],
                "attestation": ["proof_signing_alg_values_supported": ["ES256"]]
            ]
        ])

        XCTAssertEqual(
            metadata.extractSupportedProofTypes(credentialConfigurationId: credentialConfigurationId).sorted(),
            ["attestation", "jwt"]
        )
    }

    func testExtractsCryptographicBindingMethods() {
        let metadata = result(with: [
            "cryptographic_binding_methods_supported": ["jwk", "did:key"]
        ])

        XCTAssertEqual(
            metadata.extractCryptographicBindingMethods(credentialConfigurationId: credentialConfigurationId),
            ["jwk", "did:key"]
        )
    }

    func testReturnsEmptyWhenProofMetadataIsAbsent() {
        let metadata = result(with: ["format": "ldp_vc"])

        XCTAssertTrue(metadata.extractJwtProofSigningAlgorithms(credentialConfigurationId: credentialConfigurationId).isEmpty)
        XCTAssertTrue(metadata.extractSupportedProofTypes(credentialConfigurationId: credentialConfigurationId).isEmpty)
        XCTAssertTrue(metadata.extractCryptographicBindingMethods(credentialConfigurationId: credentialConfigurationId).isEmpty)
    }

    func testReturnsEmptyWhenCredentialConfigurationIsAbsent() {
        let metadata = result(with: ["format": "ldp_vc"])

        XCTAssertTrue(metadata.extractJwtProofSigningAlgorithms(credentialConfigurationId: "unknown").isEmpty)
        XCTAssertTrue(metadata.extractSupportedProofTypes(credentialConfigurationId: "unknown").isEmpty)
        XCTAssertTrue(metadata.extractCryptographicBindingMethods(credentialConfigurationId: "unknown").isEmpty)
    }

    func testIgnoresMalformedProofMetadata() {
        let metadata = result(with: [
            "proof_types_supported": "jwt",
            "cryptographic_binding_methods_supported": ["jwk": true]
        ])

        XCTAssertTrue(metadata.extractJwtProofSigningAlgorithms(credentialConfigurationId: credentialConfigurationId).isEmpty)
        XCTAssertTrue(metadata.extractSupportedProofTypes(credentialConfigurationId: credentialConfigurationId).isEmpty)
        XCTAssertTrue(metadata.extractCryptographicBindingMethods(credentialConfigurationId: credentialConfigurationId).isEmpty)
    }

    func testBuildsCredentialRequestProofMetadata() {
        let metadata = result(with: [
            "proof_types_supported": ["jwt": ["proof_signing_alg_values_supported": ["ES256"]]],
            "cryptographic_binding_methods_supported": ["jwk"]
        ])

        let proofMetadata = metadata
            .toProofBindingContext(credentialConfigurationId: credentialConfigurationId)
            .toCredentialRequestProofMetadata(credentialIssuer: "https://issuer.example.com", nonce: "nonce-123")

        XCTAssertEqual(proofMetadata.credentialIssuer, "https://issuer.example.com")
        XCTAssertEqual(proofMetadata.nonce, "nonce-123")
        XCTAssertEqual(proofMetadata.proofSigningAlgorithmsSupported, ["ES256"])
        XCTAssertEqual(proofMetadata.cryptographicBindingMethodsSupported, ["jwk"])
        XCTAssertEqual(proofMetadata.proofTypesSupported, ["jwt"])
    }
}
