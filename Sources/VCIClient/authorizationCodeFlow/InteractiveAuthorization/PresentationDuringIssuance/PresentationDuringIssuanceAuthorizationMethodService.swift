import Foundation
import OpenID4VP
import OpenID4VPBridge

class PresentationDuringIssuanceAuthorizationMethodService: AuthorizationMethodService {
    private let jsonLdCanonicalizer: JsonLdCanonicalizerCallback?
    private let selectCredentialsForPresentation: SelectCredentialsForPresentationCallback
    private let signVerifiablePresentation: SignVerifiablePresentationCallback
    private let openId4vp: OpenID4VPInteracting
    private let networkManager: NetworkManager

    init(
        jsonLdCanonicalizer: JsonLdCanonicalizerCallback?,
        openid4vpWalletConfig: WalletConfig,
        selectCredentialsForPresentation: @escaping SelectCredentialsForPresentationCallback,
        signVerifiablePresentation: @escaping SignVerifiablePresentationCallback,
        networkManager: NetworkManager = NetworkManager.shared,
        openId4vp: OpenID4VPInteracting? = nil
    ) {
        self.jsonLdCanonicalizer = jsonLdCanonicalizer
        self.selectCredentialsForPresentation = selectCredentialsForPresentation
        self.signVerifiablePresentation = signVerifiablePresentation
        self.openId4vp = openId4vp ?? OpenID4VPInteraction(jsonLdCanonicalizer: jsonLdCanonicalizer, traceabilityId: Util.getTraceabilityId(), openid4vpWalletConfig: openid4vpWalletConfig)
        self.networkManager = networkManager
    }

    func type() -> String {
        return InteractionType.openId4VpPresentationIAE.rawValue
    }

    func authorizeUser(requestData: AuthorizationRequestData) async throws -> AuthorizationResponse {
        guard let presentationRequestData = requestData as? PresentationDuringIssuanceRequestData else {
            throw InteractiveAuthorizationException(
                message: "Expected PresentationDuringIssuanceRequestData"
            )
        }

        let vpResponse: [String: Any]

        do {
            do {
                let vpRequest = try await validatePresentationRequest(request: presentationRequestData.ovpRequest)
                vpResponse = try await handlePresentation(vpRequest: vpRequest)
            } catch {
                Util.logWarning(
                    message: "Error during presentation handling: \(error.localizedDescription)",
                    className: "PresentationDuringIssuanceAuthorizationMethodService"
                )
                vpResponse = openId4vp.constructErrorInfo(exception: error)
            }

            return try await sendOVPAuthorizationResponseToIssuer(
                iar: presentationRequestData.iar,
                authSession: presentationRequestData.authSession,
                vpResponse: vpResponse
            )

        } catch let ex as InteractiveAuthorizationException {
            throw ex

        } catch let ex as VCIClientException {
            throw InteractiveAuthorizationException(
                message: "Error during presentation authorization: \(ex.message)",
                issuerErrorCode: ex.issuerErrorCode,
                issuerErrorDescription: ex.issuerErrorDescription,
                cause: ex
            )

        } catch {
            throw InteractiveAuthorizationException(
                message: "Unexpected error during presentation authorization: \(error.localizedDescription)",
                cause: error
            )
        }
    }

    private func validatePresentationRequest(request: [String: Any]) async throws -> AuthorizationRequest {
        let authorizationRequest = try await openId4vp.authenticateVerifier(authRequest: request)
        guard authorizationRequest.responseMode == "iar-post"
           || authorizationRequest.responseMode == "iar-post.jwt"
           || authorizationRequest.responseMode == "iae_post"
           || authorizationRequest.responseMode == "iae_post.jwt" else {
            throw IllegalArgumentException(
                "response_mode must be 'iar-post', 'iar-post.jwt', 'iae_post' or 'iae_post.jwt'"
            )
        }
        return authorizationRequest
    }

    private func handlePresentation(vpRequest: AuthorizationRequest) async throws -> [String: Any] {
        let selectedCredentials: [String: [Credential]] = try await selectCredentialsForPresentation(vpRequest)
        if selectedCredentials.isEmpty {
            throw AccessDenied(message: "No credentials selected by user", className: "PresentationDuringIssuanceAuthorizationMethodService")
        }

        let unsignedVpTokens: [UnsignedVPToken] = try await openId4vp.constructUnsignedVPToken(
            selectedCredentials: selectedCredentials
        )
        let signedVpTokens: [VPTokenSigningResult] = try await signVerifiablePresentation(unsignedVpTokens)

        return openId4vp.constructVPResponse(vpTokenSigningResults: signedVpTokens)
    }

    private func extractHolderId(credentials: [String: [FormatType: [OpenID4VPAnyCodable]]]) -> String? {
        return credentials.values.compactMap { formatMap in
            guard let ldpVcCredentials = formatMap[.ldp_vc],
                  let firstLdpVcCredential = ldpVcCredentials.first?.value as? [String: Any],
                  let credentialSubject = firstLdpVcCredential["credentialSubject"] as? [String: Any],
                  let holderId = credentialSubject["id"] as? String else {
                return nil
            }
            return holderId.trimmingCharacters(in: CharacterSet(charactersIn: "=")) + "#0"
        }.first
    }

    private func sendOVPAuthorizationResponseToIssuer(
        iar: String,
        authSession: String,
        vpResponse: [String: Any]
    ) async throws -> AuthorizationResponse {
        let response: NetworkResponse

        do {
            let vpResponseData = try JSONSerialization.data(withJSONObject: vpResponse)
            guard let vpResponseString = String(data: vpResponseData, encoding: .utf8) else {
                throw InteractiveAuthorizationException(
                    message: "Failed to serialize VP response"
                )
            }

            response = try await networkManager.sendRequest(
                url: iar,
                method: .post,
                headers: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue],
                bodyParams: [
                    "openid4vp_response": vpResponseString,
                    "auth_session": authSession,
                ]
            )

        } catch let ex as InteractiveAuthorizationException {
            throw ex
        } catch let ex as VCIClientException {
            throw InteractiveAuthorizationException(
                message: "Error while posting VP response: \(ex.message)",
                issuerErrorCode: ex.issuerErrorCode,
                issuerErrorDescription: ex.issuerErrorDescription,
                cause: ex
            )

        } catch {
            throw InteractiveAuthorizationException(
                message: "Unexpected error while posting VP response: \(error.localizedDescription)",
                cause: error
            )
        }

        do {
            guard let data = response.body.data(using: .utf8) else {
                throw InteractiveAuthorizationException(
                    message: "Issuer response is not valid UTF-8"
                )
            }

            return try JSONDecoder().decode(AuthorizationResponse.self, from: data)

        } catch {
            throw InteractiveAuthorizationException(
                message: "Issuer response deserialization failed",
                cause: error
            )
        }
    }
}
