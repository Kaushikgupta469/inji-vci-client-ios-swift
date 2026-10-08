import Foundation

public struct IssuerMetadata : Codable{
    public let credentialIssuer: String
    public let credentialEndpoint: String
    public let credentialType: [String]?
    public let context: [String]?
    public let credentialFormat: CredentialFormat
    public let doctype: String?
    public let claims: [String: AnyCodable]?
    public let authorizationServers: [String]?
    public let tokenEndpoint: String?
    public let nonceEndpoint: String?
    public let vct: String?
    public let scope: String?
    public let specVersion: OID4VCIVersion

    public init(
        credentialIssuer: String,
        credentialEndpoint: String,
        credentialType: [String]? = nil,
        context: [String]? = nil,
        credentialFormat: CredentialFormat,
        doctype: String? = nil,
        claims: [String: AnyCodable]? = nil,
        authorizationServers: [String]? = nil,
        tokenEndpoint: String? = nil,
        nonceEndpoint: String? = nil,
        vct: String? = nil,
        scope: String = "openId",
        specVersion: OID4VCIVersion = .v1
    ) {
        self.credentialIssuer = credentialIssuer
        self.credentialEndpoint = credentialEndpoint
        self.credentialType = credentialType
        self.context = context
        self.credentialFormat = credentialFormat
        self.doctype = doctype
        self.claims = claims
        self.authorizationServers = authorizationServers
        self.tokenEndpoint = tokenEndpoint
        self.nonceEndpoint = nonceEndpoint
        self.vct = vct
        self.scope = scope
        self.specVersion = specVersion
    }
}
