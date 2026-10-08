import Foundation

class NonceService {
    private let session: NetworkManager

    init(session: NetworkManager = NetworkManager.shared) {
        self.session = session
    }

    static func extractNonceFromTokenResponse(_ tokenResponse: TokenResponse) throws -> String? {
        if let cNonce = tokenResponse.cNonce, !cNonce.isEmpty {
            return cNonce
        }
        return nil
    }

    func fetchNonce(
        issuerMetadata: IssuerMetadata,
        timeoutInMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        dpopManager: DPoPManager? = nil
    ) async throws -> String? {
        guard let nonceEndpoint = issuerMetadata.nonceEndpoint, !nonceEndpoint.isEmpty else {
            return nil
        }

        let response = try await session.sendRawRequest(
            url: nonceEndpoint,
            method: .post,
            headers: [
                Header.accept.rawValue: ContentTypes.applicationJson.rawValue,
                Header.contentType.rawValue: ContentTypes.applicationJson.rawValue
            ],
            body: Data("{}".utf8),
            timeoutMillis: timeoutInMillis
        )

        dpopManager?.updateNonce(NonceService.header(Constants.dpopNonceHeader, in: response.headers))

        guard let nonceResponse = try JsonUtils.deserialize(response.body, as: NonceResponse.self) else {
            throw DownloadFailedException("Failed to parse nonce response.")
        }

        guard let cNonce = nonceResponse.cNonce, !cNonce.isEmpty else {
            throw DownloadFailedException("Failed to parse nonce response.")
        }

        return cNonce
    }

    private static func header(_ name: String, in headers: [AnyHashable: Any]?) -> String? {
        guard let headers = headers else { return nil }
        for (key, value) in headers {
            if let keyString = key as? String, keyString.caseInsensitiveCompare(name) == .orderedSame {
                return value as? String
            }
        }
        return nil
    }
}

private struct NonceResponse: Decodable {
    let cNonce: String?

    enum CodingKeys: String, CodingKey {
        case cNonce = "c_nonce"
    }
}
