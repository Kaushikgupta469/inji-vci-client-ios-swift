import Foundation

class PushedAuthorizationRequestException: VCIClientException {
    init(_ message: String?) {
        super.init(
            code: "VCI-014",
            message: "Pushed authorization request failed: \(message ?? "")"
        )
    }

    init(
        message: String?,
        issuerErrorCode: String? = nil,
        issuerErrorDescription: String? = nil,
        cause: Error? = nil
    ) {
        super.init(
            code: "VCI-014",
            message: "Pushed authorization request failed: \(message ?? "")",
            issuerErrorCode: issuerErrorCode,
            issuerErrorDescription: issuerErrorDescription,
            cause: cause
        )
    }
}
