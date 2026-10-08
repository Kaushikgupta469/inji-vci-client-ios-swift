import Foundation

class DPoPException: VCIClientException {
    init(_ message: String?) {
        super.init(
            code: "VCI-013",
            message: message ?? ""
        )
    }

    init(
        message: String?,
        issuerErrorCode: String? = nil,
        issuerErrorDescription: String? = nil,
        cause: Error? = nil
    ) {
        super.init(
            code: "VCI-013",
            message: message ?? "",
            issuerErrorCode: issuerErrorCode,
            issuerErrorDescription: issuerErrorDescription,
            cause: cause
        )
    }
}
