import Foundation

/* Modify according to use case in trusted issuer flow
   KeyTypes supported : Ed25519, EC (P-256)
   VCFormats supported : ldp_vc, mso_mdoc
 */

// MARK: - Mock Issuer (ldp_vc / Ed25519)
let credentialIssuer = "https://injicertify-mock.qa-inji1.mosip.net"
let credentialConfigurationId = "MockVerifiableCredential"
let clientId = "mpartner-default-mimoto-mock-oidc"
let redirectUri = "io.mosip.residentapp.inji://oauthredirect"
let proxyTokenEndpoint = "https://api.qa-inji1.mosip.net/v1/mimoto/get-token/Mock"

// MARK: - MDL Issuer (mso_mdoc / ES256)
let mdlCredentialIssuer = "https://injicertify-mock.qa-inji1.mosip.net"
let mdlCredentialConfigurationId = "DrivingLicenseCredential"
let mdlClientId = "mpartner-default-mimoto-mock-oidc"
let mdlRedirectUri = "io.mosip.residentapp.inji://oauthredirect"
let mdlProxyTokenEndpoint = "https://api.qa-inji1.mosip.net/v1/mimoto/get-token/Mock"
