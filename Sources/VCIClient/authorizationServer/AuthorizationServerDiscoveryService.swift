import Foundation

class AuthorizationServerDiscoveryService {
    func discover(baseUrl: String) async throws -> AuthorizationServerMetadata {
        let timeout = Constants.defaultNetworkTimeoutInMillis

        for wellKnownUrl in Self.buildCandidateWellKnownUrls(baseUrl: baseUrl) {
            do {
                let response = try await NetworkManager.shared.sendRequest(
                    url: wellKnownUrl,
                    method: .get,
                    timeoutMillis: timeout
                )

                if !response.body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                   let metadata = try JsonUtils.deserialize(response.body, as: AuthorizationServerMetadata.self) {
                    return metadata
                }
            } catch {
                Util.logWarning(
                    message: "Discovery failed at \(wellKnownUrl), trying next candidate: \(error.localizedDescription)",
                    className: "AuthorizationServerDiscoveryService"
                )
            }
        }

        throw AuthorizationServerDiscoveryException("Failed to discover authorization server metadata at all well-known endpoints.")
    }

    /// Candidate discovery URLs in priority order: the ``WellKnownUrl`` inserted form followed by
    /// the legacy append form, for both well-known suffixes.
    static func buildCandidateWellKnownUrls(baseUrl: String) -> [String] {
        let oauthSuffix = "/.well-known/oauth-authorization-server"
        let openidSuffix = "/.well-known/openid-configuration"
        var normalized = baseUrl
        while normalized.hasSuffix("/") { normalized.removeLast() }

        var candidates: [String] = []
        if let oauth = WellKnownUrl.insertSuffix(baseUrl: normalized, suffix: oauthSuffix) {
            candidates.append(oauth)
        }
        if let openid = WellKnownUrl.insertSuffix(baseUrl: normalized, suffix: openidSuffix) {
            candidates.append(openid)
        }
        let appendedOauth = "\(normalized)\(oauthSuffix)"
        if !candidates.contains(appendedOauth) {
            candidates.append(appendedOauth)
            candidates.append("\(normalized)\(openidSuffix)")
        }
        return candidates
    }
}
