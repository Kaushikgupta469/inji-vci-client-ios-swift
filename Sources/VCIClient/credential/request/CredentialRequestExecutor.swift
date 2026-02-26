import Foundation

class CredentialRequestExecutor {
    private let factory: CredentialRequestFactoryProtocol

    init(factory: CredentialRequestFactoryProtocol = CredentialRequestFactory()) {
        self.factory = factory
    }

    private var logTag: String {
        Util.getLogTag(className: String(describing: type(of: self)))
    }

    func requestCredential(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proof: Proof,
        accessToken: String,
        timeoutInMillis: Int64 = 10000,
        session: NetworkManager = NetworkManager.shared
    ) async throws -> CredentialResponse? {
        do {
            var request = try factory.createCredentialRequest(
                credentialFormat: issuerMetadata.credentialFormat,
                accessToken: accessToken,
                issuer: issuerMetadata,
                proofJwt: proof
            )

            if let bodyData = request.httpBody, let bodyString = String(data: bodyData, encoding: .utf8) {
                print("\(logTag) [VCI-DEBUG] Credential Request Body for format \(issuerMetadata.credentialFormat.rawValue): \(bodyString)")
            }

            request.timeoutInterval = TimeInterval(timeoutInMillis) / 1000

            let networkResponse = try await session.sendRequest(request: request)
            let responseBody = networkResponse.body

            print("\(logTag) Credential downloaded successfully.")

            if !responseBody.isEmpty {
                guard var result = try JsonUtils.deserialize(responseBody, as: CredentialResponse.self) else {
                    throw DownloadFailedException("Failed to parse credential response.")
                }
                result.credentialConfigurationId = credentialConfigurationId
                result.credentialIssuer = issuerMetadata.credentialIssuer
                return result
            }

            print("\(logTag) Response body is empty.")
            return nil

        } catch let error as NetworkRequestTimeoutException {
            print("\(logTag) Request timed out after \(timeoutInMillis / 1000)s")
            throw error
        } catch let error as DownloadFailedException {
            throw error
        } catch let error as InvalidAccessTokenException {
            throw error
        } catch let error as InvalidPublicKeyException {
            throw error
        } catch {
            print("\(logTag) Unexpected error: \(error.localizedDescription)")
            throw DownloadFailedException(error.localizedDescription)
        }
    }
}
