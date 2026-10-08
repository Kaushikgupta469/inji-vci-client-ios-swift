import Foundation

struct IssuerMetadataResult {
    var issuerMetadata: IssuerMetadata
    let raw: [String: Any?]
    let credentialIssuer: String?

    init(issuerMetadata: IssuerMetadata, raw: [String: Any?], credentialIssuer: String? = nil) {
        self.issuerMetadata = issuerMetadata
        self.raw = raw
        self.credentialIssuer = credentialIssuer
    }
    
    func extractJwtProofSigningAlgorithms(
        credentialConfigurationId: String
    ) -> [String] {
        guard
            let proofTypes = proofTypesSupported(credentialConfigurationId: credentialConfigurationId),
            let jwt = proofTypes["jwt"] as? [String: Any],
            let algos = jwt["proof_signing_alg_values_supported"] as? [Any]
        else {
            return []
        }

        return algos.compactMap { $0 as? String }
    }

    func extractSupportedProofTypes(credentialConfigurationId: String) -> [String] {
        guard let proofTypes = proofTypesSupported(credentialConfigurationId: credentialConfigurationId)
        else {
            return []
        }

        return Array(proofTypes.keys)
    }

    func extractCryptographicBindingMethods(credentialConfigurationId: String) -> [String] {
        guard
            let config = credentialConfiguration(credentialConfigurationId: credentialConfigurationId),
            let bindingMethods = config["cryptographic_binding_methods_supported"] as? [String]
        else {
            return []
        }

        return bindingMethods
    }

    private func credentialConfiguration(credentialConfigurationId: String) -> [String: Any]? {
        guard
            let configurations = raw["credential_configurations_supported"] as? [String: Any],
            let config = configurations[credentialConfigurationId] as? [String: Any]
        else {
            return nil
        }

        return config
    }

    private func proofTypesSupported(credentialConfigurationId: String) -> [String: Any]? {
        credentialConfiguration(credentialConfigurationId: credentialConfigurationId)?["proof_types_supported"] as? [String: Any]
    }
}
