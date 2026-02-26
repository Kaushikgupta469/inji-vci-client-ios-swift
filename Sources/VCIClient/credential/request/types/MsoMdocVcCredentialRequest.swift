import Foundation

class MsoMdocVcCredentialRequest: CredentialRequestProtocol {
    let accessToken: String
    let issuerMetaData: IssuerMetadata
    let proof: JWTProof

    required init(accessToken: String, issuerMetaData: IssuerMetadata, proof: JWTProof) {
        self.accessToken = accessToken
        self.issuerMetaData = issuerMetaData
        self.proof = proof
    }

    func validateIssuerMetadata() -> ValidatorResult {
        let validatorResult = ValidatorResult()
        if issuerMetaData.doctype.isBlank() {
            validatorResult.addInvalidField("docType")
        }
        return validatorResult
    }

    func constructRequest() throws -> URLRequest {
        var request = URLRequest(url: URL(string: issuerMetaData.credentialEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        guard let requestBody = try generateRequestBody() else {
            throw DownloadFailedException("")
        }
        request.httpBody = requestBody

        return request
    }

    private func generateRequestBody() throws -> Data? {
        let logTag = Util.getLogTag(className: String(describing: type(of: self)))

        guard let doctype = issuerMetaData.doctype else {
            throw DownloadFailedException("Missing doctype in issuer metadata")
        }

        let claims = issuerMetaData.claims.map { Util.convertToAnyCodable(dict: $0) }

        let credentialRequestBody = MsoMdocCredentialRequestBody(
            format: issuerMetaData.credentialFormat,
            doctype: doctype,
            claims: claims,
            proof: proof as JWTProof
        )

        do {
            return try JSONEncoder().encode(credentialRequestBody)
        } catch {
            print(logTag, "Error occurred while constructing request body: \(error.localizedDescription)")
            throw DownloadFailedException("Failed to encode credential request body")
        }
    }
}
struct MsoMdocCredentialRequestBody: Encodable {
    let format: CredentialFormat
    let proof: JWTProof
    let doctype: String
    let claims: [String: AnyCodable]?

    init(format: CredentialFormat, doctype: String, claims: [String: AnyCodable]?, proof: JWTProof) {
        self.format = format
        self.doctype = doctype
        self.proof = proof
        self.claims = claims
    }
}