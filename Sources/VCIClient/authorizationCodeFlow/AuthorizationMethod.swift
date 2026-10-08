import Foundation
import OpenID4VP

public enum AuthorizationMethod {
    case redirectToWeb(
        openWebPage: OpenWebPageCallback
    )

    case presentationDuringIssuance(
        jsonLdCanonicalizer: JsonLdCanonicalizerCallback? = nil,
        openid4vpWalletConfig: WalletConfig = WalletConfig(),
        selectCredentialsForPresentation: SelectCredentialsForPresentationCallback,
        signVerifiablePresentation: SignVerifiablePresentationCallback
    )

    var type: InteractionType {
        switch self {
        case .redirectToWeb:
            return .redirectToWeb
        case .presentationDuringIssuance:
            return .openId4VpPresentationIAE
        }
    }
}
