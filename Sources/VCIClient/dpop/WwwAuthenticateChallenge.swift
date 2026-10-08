import Foundation

struct WwwAuthenticateChallenge {
    let isDpop: Bool
    let isBearer: Bool
    let error: String?

    static func parse(_ headerValue: String?) -> WwwAuthenticateChallenge {
        guard let headerValue = headerValue,
              !headerValue.trimmingCharacters(in: .whitespaces).isEmpty else {
            return WwwAuthenticateChallenge(isDpop: false, isBearer: false, error: nil)
        }

        let isDpop = headerValue.range(
            of: "(^|,|\\s)DPoP(\\s|,|$)",
            options: [.regularExpression, .caseInsensitive]
        ) != nil

        let isBearer = headerValue.range(
            of: "(^|,|\\s)Bearer(\\s|,|$)",
            options: [.regularExpression, .caseInsensitive]
        ) != nil

        var error: String?
        if let match = headerValue.range(
            of: "error\\s*=\\s*\"([^\"]+)\"",
            options: [.regularExpression, .caseInsensitive]
        ) {
            let segment = String(headerValue[match])
            if let valueRange = segment.range(
                of: "\"([^\"]+)\"",
                options: .regularExpression
            ) {
                error = String(segment[valueRange]).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            }
        }

        return WwwAuthenticateChallenge(isDpop: isDpop, isBearer: isBearer, error: error)
    }
}
