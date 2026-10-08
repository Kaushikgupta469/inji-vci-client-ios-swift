@testable import VCIClient
import XCTest

final class AuthorizationServerResolverTests: XCTestCase {
    func test_singleAuthServerInMetadata_shouldResolve() async throws {
        let url = "https://auth1.example.com"
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.mockMetadataByUrl[url] = AuthorizationServerMetadata(
            issuer: url,
            grantTypesSupported: ["authorization_code"], tokenEndpoint: "https://mock-token",
            authorizationEndpoint: "\(url)/auth", interactiveAuthorizationEndpoint: nil,
            requireInteractiveAuthorizationRequest: nil, dpopSigningAlgValuesSupported: nil
        )

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(credentialIssuer: url, credentialEndpoint: "", credentialFormat: CredentialFormat.ldp_vc, authorizationServers: [url])
        let offer = CredentialOffer(
            credentialIssuer: "https://mock-issuer", credentialConfigurationIds: ["mock-cred"], grants: nil
        )

        let metadata = try await resolver.resolveForAuthCode(issuerMetadata: issuer, credentialOffer: offer)

        XCTAssertEqual(metadata.issuer, url)
    }

    func test_grantAuthServer_shouldOverrideMetadata() async throws {
        let overrideUrl = "https://grant-override.com"
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.mockMetadataByUrl[overrideUrl] = AuthorizationServerMetadata(
            issuer: overrideUrl,
            grantTypesSupported: ["authorization_code"], tokenEndpoint: "mock",
            authorizationEndpoint: "\(overrideUrl)/auth",
            interactiveAuthorizationEndpoint: nil,
            requireInteractiveAuthorizationRequest: nil, dpopSigningAlgValuesSupported: nil
        )

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(credentialIssuer: overrideUrl, credentialEndpoint: "", credentialFormat: CredentialFormat.ldp_vc, authorizationServers: ["https://unused.com", "https://grant-override.com"])
        let offer = CredentialOffer(credentialIssuer: "https://mock", credentialConfigurationIds: ["mock-id"], grants: CredentialOfferGrants(
            preAuthorizedGrant: nil, authorizationCodeGrant: AuthorizationCodeGrant(issuerState: nil, authorizationServer: overrideUrl)
        ))

        let metadata = try await resolver.resolveForAuthCode(issuerMetadata: issuer, credentialOffer: offer)

        XCTAssertEqual(metadata.issuer, overrideUrl)
    }

    func test_multipleAuthServers_firstValidShouldWin() async throws {
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.urlsThatThrow.insert("https://fail.com")
        mockDiscovery.mockMetadataByUrl["https://valid.com"] = AuthorizationServerMetadata(
            issuer: "https://valid.com",
            grantTypesSupported: ["authorization_code"], tokenEndpoint: "mock-token",
            authorizationEndpoint: "https://valid.com/auth",
            interactiveAuthorizationEndpoint: nil,
            requireInteractiveAuthorizationRequest: nil, dpopSigningAlgValuesSupported: nil
        )

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(
            credentialIssuer: "https://fallback.com",
            credentialEndpoint: "mock",
            credentialFormat: CredentialFormat.ldp_vc,
            authorizationServers: ["https://fail.com", "https://valid.com"]
        )
        let offer = CredentialOffer(credentialIssuer: "https://fallback.com", credentialConfigurationIds: ["mock-id"], grants: nil)

        let metadata = try await resolver.resolveForAuthCode(issuerMetadata: issuer, credentialOffer: offer)

        XCTAssertEqual(metadata.issuer, "https://valid.com")
    }

    func test_allServersInvalid_shouldThrow() async {
        let urls = ["https://bad1.com", "https://bad2.com", "https://fallback.com"]
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.urlsThatThrow = Set(urls)

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(
            credentialIssuer: "https://fallback.com",
            credentialEndpoint: "mock",
            credentialFormat: CredentialFormat.ldp_vc,
            authorizationServers: urls
        )

        do {
            _ = try await resolver.resolveForAuthCode(issuerMetadata: issuer)
            XCTFail("Expected AuthServerDiscoveryException but no error was thrown")
        } catch let error as AuthorizationServerDiscoveryException {
            XCTAssertTrue(error.message.contains("None of the authorization servers"))
        } catch {
            XCTFail("Expected AuthServerDiscoveryException, but got \(type(of: error)): \(error)")
        }
    }

    func test_fallbackToCredentialIssuer_shouldWork() async throws {
        let fallback = "https://fallback-issuer.com"
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.mockMetadataByUrl[fallback] = AuthorizationServerMetadata(
            issuer: fallback,
            grantTypesSupported: ["authorization_code"], tokenEndpoint: "mock-token",
            authorizationEndpoint: "\(fallback)/auth",
            interactiveAuthorizationEndpoint: nil,
            requireInteractiveAuthorizationRequest: nil, dpopSigningAlgValuesSupported: nil
        )

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(
            credentialIssuer: fallback,
            credentialEndpoint: "mock",
            credentialFormat: CredentialFormat.ldp_vc,
            authorizationServers: nil
        )

        let metadata = try await resolver.resolveForAuthCode(issuerMetadata: issuer)

        XCTAssertEqual(metadata.issuer, fallback)
    }

    func test_issuerMismatch_shouldThrow() async {
        let realUrl = "https://expected.com"
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.mockMetadataByUrl[realUrl] = AuthorizationServerMetadata(
            issuer: "https://mismatch.com",
            grantTypesSupported: ["authorization_code"], tokenEndpoint: "mock",
            authorizationEndpoint: "\(realUrl)/auth",
            interactiveAuthorizationEndpoint: nil,
            requireInteractiveAuthorizationRequest: nil, dpopSigningAlgValuesSupported: nil

        )

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(
            credentialIssuer: "mock",
            credentialEndpoint: "mock",
            credentialFormat: CredentialFormat.ldp_vc,
            authorizationServers: [realUrl]
        )

        do {
            _ = try await resolver.resolveForAuthCode(issuerMetadata: issuer)
            XCTFail("Expected AuthServerDiscoveryException but no error was thrown")
        } catch let error as AuthorizationServerDiscoveryException {
            XCTAssertTrue(error.message.contains("Issuer mismatch"))
        } catch {
            XCTFail("Expected AuthServerDiscoveryException, but got \(type(of: error)): \(error)")
        }
    }

    func test_unsupportedGrantType_shouldThrow() async {
        let url = "https://auth.example.com"
        let mockDiscovery = MockAuthServerDiscoveryService()
        mockDiscovery.mockMetadataByUrl[url] = AuthorizationServerMetadata(
            issuer: url,
            grantTypesSupported: ["implicit"], tokenEndpoint: "mock",
            authorizationEndpoint: "\(url)/auth",
            interactiveAuthorizationEndpoint: nil,
            requireInteractiveAuthorizationRequest: nil, dpopSigningAlgValuesSupported: nil
        )

        let resolver = AuthorizationServerResolver(authServerDiscoveryService: mockDiscovery)
        let issuer = IssuerMetadata(
            credentialIssuer: "mock",
            credentialEndpoint: "mock",
            credentialFormat: CredentialFormat.ldp_vc,
            authorizationServers: [url]
        )

        do {
            _ = try await resolver.resolveForAuthCode(issuerMetadata: issuer)
            XCTFail("Expected AuthServerDiscoveryException but no error was thrown")
        } catch let error as AuthorizationServerDiscoveryException {
            print("---------",error.localizedDescription)
            XCTAssertTrue(error.message.contains("not supported"))
        } catch {
            XCTFail("Expected AuthServerDiscoveryException, but got \(type(of: error)): \(error)")
        }
    }

}
