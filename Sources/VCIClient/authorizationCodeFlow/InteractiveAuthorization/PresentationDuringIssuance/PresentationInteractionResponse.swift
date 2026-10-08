import Foundation

final class PresentationInteractionResponse: InteractionResponse, Decodable {
    var openid4vpRequest: [String: Any]

    private enum CodingKeys: String, CodingKey {
        case status
        case type
        case authSession = "auth_session"
        case openid4vpRequest = "openid4vp_request"
    }

    init(json: [String: Any]) throws {
        guard let request = json["openid4vp_request"] as? [String: Any] else {
            throw IllegalArgumentException("Missing or invalid 'openid4vp_request'")
        }
        self.openid4vpRequest = request
        
        try super.init(status: json["status"] as? String, type: json["type"] as? String, authSession: json["auth_session"] as? String)
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let status = try container.decode(String.self, forKey: .status)
        let type = try container.decode(String.self, forKey: .type)
        let authSession = try container.decode(String.self, forKey: .authSession)

        if let nestedDecoder = try? container.superDecoder(forKey: .openid4vpRequest) {
            let any = try PresentationInteractionResponse.decodeAny(from: nestedDecoder)
            guard let dict = any as? [String: Any] else {
                throw ValidationError.invalid("openid4vp_request")
            }
            self.openid4vpRequest = dict
        } else {
            let data = try container.decode(Data.self, forKey: .openid4vpRequest)
            let obj = try JSONSerialization.jsonObject(with: data, options: [])
            guard let dict = obj as? [String: Any] else {
                throw ValidationError.invalid("openid4vp_request")
            }
            self.openid4vpRequest = dict
        }
        try super.init(status: status, type: type,  authSession: authSession)
    }

    private static func decodeAny(from decoder: Decoder) throws -> Any {
        if var arrayContainer = try? decoder.unkeyedContainer() {
            var arr: [Any] = []
            while !arrayContainer.isAtEnd {
                let valueDecoder = try arrayContainer.superDecoder()
                let value = try decodeAny(from: valueDecoder)
                arr.append(value)
            }
            return arr
        }
        if let container = try? decoder.container(keyedBy: DynamicCodingKeys.self) {
            var dict: [String: Any] = [:]
            for key in container.allKeys {
                let valueDecoder = try container.superDecoder(forKey: key)
                dict[key.stringValue] = try decodeAny(from: valueDecoder)
            }
            return dict
        }
        let single = try decoder.singleValueContainer()
        if single.decodeNil() { return NSNull() }
        if let b = try? single.decode(Bool.self) { return b }
        if let i = try? single.decode(Int.self) { return i }
        if let d = try? single.decode(Double.self) { return d }
        if let s = try? single.decode(String.self) { return s }
        if let data = try? single.decode(Data.self),
           let obj = try? JSONSerialization.jsonObject(with: data, options: []) {
            return obj
        }
        throw ValidationError.invalid("Unsupported JSON value")
    }

    private struct DynamicCodingKeys: CodingKey {
        var stringValue: String
        init?(stringValue: String) { self.stringValue = stringValue }
        var intValue: Int? { return nil }
        init?(intValue _: Int) { return nil }
    }
    
    override func validate() throws {
        guard let type = type,
              type == InteractionType.openId4VpPresentation.rawValue
                || type == InteractionType.openId4VpPresentationIAE.rawValue
        else {
            throw IllegalArgumentException(
                "Invalid type: expected '\(InteractionType.openId4VpPresentation.rawValue)' or '\(InteractionType.openId4VpPresentationIAE.rawValue)'"
            )
        }

        guard !openid4vpRequest.isEmpty else {
            throw IllegalArgumentException("openid4vpRequest must not be empty")
        }

    }

    enum ValidationError: Error {
        case invalidStatus(String)
        case invalidType(String)
        case blankAuthSession
        case emptyOpenId4VpRequest
        case missing(String)
        case invalid(String)
        case blank(String)

    }
}
