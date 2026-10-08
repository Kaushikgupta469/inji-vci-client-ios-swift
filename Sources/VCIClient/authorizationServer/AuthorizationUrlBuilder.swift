import Foundation

enum AuthorizationUrlBuilder {
    
    static func buildWithParameters(
        baseUrl: String,
        clientId: String,
        redirectUri: String,
        scope: String,
        responseType: AuthorizationResponseType = .code,
        state: String,
        codeChallenge: String,
        codeChallengeMethod: CodeChallengeMethod = .s256,
        nonce: String,
        dpopJkt: String
    ) -> String {
        var url = baseUrl
        url += "?client_id=\(encode(clientId))"
        url += "&redirect_uri=\(encode(redirectUri))"
        url += "&response_type=\(encode(responseType.rawValue))"
        url += "&scope=\(encode(scope))"
        url += "&state=\(encode(state))"
        url += "&code_challenge=\(encode(codeChallenge))"
        url += "&code_challenge_method=\(encode(codeChallengeMethod.rawValue))"
        url += "&nonce=\(encode(nonce))"
        url += "&dpop_jkt=\(encode(dpopJkt))"
        return url
    }

    static func buildWithRequestUri(
        baseUrl: String,
        clientId: String,
        requestUri: String
    ) -> String {
        var url = baseUrl
        url += "?client_id=\(encode(clientId))"
        url += "&request_uri=\(encode(requestUri))"
        return url
    }

    private static func encode(_ value: String) -> String {
        return value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
    }
}

