import Foundation

struct PushedAuthorizationResponse: Codable {
    let requestUri: String
    let expiresIn: Int64?

    enum CodingKeys: String, CodingKey {
        case requestUri = "request_uri"
        case expiresIn = "expires_in"
    }
}
