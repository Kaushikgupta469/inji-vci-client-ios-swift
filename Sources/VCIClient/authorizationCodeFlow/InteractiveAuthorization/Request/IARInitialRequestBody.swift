import Foundation

struct IARInitialRequestBody: Codable {
    let responseType: String
    let clientId: String
    let codeChallenge: String
    let codeChallengeMethod: String
    let redirectUri: String
    let authorizationDetails: [AuthorizationDetails]
    let interactionTypesSupported: [String]
    let dpopJkt: String

    enum CodingKeys: String, CodingKey {
        case responseType = "response_type"
        case clientId = "client_id"
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
        case redirectUri = "redirect_uri"
        case authorizationDetails = "authorization_details"
        case interactionTypesSupported = "interaction_types_supported"
        case dpopJkt = "dpop_jkt"
    }

    init(
        clientId: String,
        codeChallenge: String,
        redirectUri: String,
        authorizationDetails: [AuthorizationDetails],
        interactionTypesSupported: [String],
        responseType: String = "code",
        codeChallengeMethod: String = "S256",
        dpopJkt: String
    ) {
        self.responseType = responseType
        self.clientId = clientId
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.redirectUri = redirectUri
        self.authorizationDetails = authorizationDetails
        self.interactionTypesSupported = interactionTypesSupported
        self.dpopJkt = dpopJkt
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(responseType, forKey: .responseType)
        try container.encode(clientId, forKey: .clientId)
        try container.encode(codeChallenge, forKey: .codeChallenge)
        try container.encode(codeChallengeMethod, forKey: .codeChallengeMethod)
        try container.encode(redirectUri, forKey: .redirectUri)
        try container.encode(authorizationDetails, forKey: .authorizationDetails)

        let interactionTypes = interactionTypesSupported.joined(separator: ",")
        try container.encode(interactionTypes, forKey: .interactionTypesSupported)
        try container.encode(dpopJkt, forKey: .dpopJkt)
    }

    func toFormMap() -> [String: String] {
        let authDetailsJson: String = JsonUtils.encode(authorizationDetails, empty: "[]")

        return [
            "response_type": responseType,
            "client_id": clientId,
            "code_challenge": codeChallenge,
            "code_challenge_method": codeChallengeMethod,
            "redirect_uri": redirectUri,
            "authorization_details": authDetailsJson,
            "interaction_types_supported": interactionTypesSupported.joined(separator: ","),
            "dpop_jkt": dpopJkt
        ]
    }
}
