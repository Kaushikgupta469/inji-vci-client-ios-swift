import OpenID4VP
import OpenID4VPBridge

public typealias AuthorizeUserCallback = (_ authorizationUrl: String) async throws -> String
public typealias TokenResponseCallback = (_ tokenRequest: TokenRequest) async throws -> TokenResponse
typealias ProofJwtCallback = (_ credentialRequestProofMetadata: CredentialRequestProofMetadata) async throws -> String
public typealias ProofsCallback = (_ credentialRequestProofMetadata: CredentialRequestProofMetadata) async throws -> CredentialRequestProofs
public typealias CheckIssuerTrustCallback = ((_ credentialIssuer: String, _ issuerDisplay: [[String: Any]]) async throws -> Bool)?
public typealias TxCodeCallback = ((_ inputMode: String?, _ description: String?, _ length: Int?) async throws -> String)?

public typealias SelectCredentialsForPresentationCallback = (_ ovpRequest: AuthorizationRequest) async throws -> [String : [Credential]]
public typealias SignVerifiablePresentationCallback = (_ payload: [UnsignedVPToken]) async throws -> [VPTokenSigningResult]

public typealias OpenWebPageCallback = (_ url: String) async throws -> [String: Any]
