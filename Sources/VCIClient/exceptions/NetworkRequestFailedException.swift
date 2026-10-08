import Foundation

class NetworkRequestFailedException: VCIClientException {
    let httpStatusCode: Int?
    let headers: [AnyHashable: Any]?

    init(_ message: String?) {
        httpStatusCode = nil
        headers = nil
        super.init(
            code: "VCI-006",
            message: "Network request failed, details - \(message ?? "")"
        )
    }

    init(
        message: String?,
        httpStatusCode: Int? = nil,
        headers: [AnyHashable: Any]? = nil,
        issuerErrorCode: String? = nil,
        issuerErrorDescription: String? = nil,
        cause: Error? = nil
    ) {
        self.httpStatusCode = httpStatusCode
        self.headers = headers
        super.init(
            code: "VCI-006",
            message: "Network request failed, details - \(message ?? "")",
            issuerErrorCode: issuerErrorCode,
            issuerErrorDescription: issuerErrorDescription,
            cause: cause
        )
    }
}
