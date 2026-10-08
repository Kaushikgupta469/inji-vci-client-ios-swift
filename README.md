# INJI VCI Client

The **Inji-Vci-Client-iOS-Swift** is a Swift library that simplifies credential issuance via the [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) protocol. It handles the full credential download lifecycle — issuer discovery, authorization, proof construction, and credential retrieval — so your wallet can focus on user experience and key management.

---

## Table of Contents

- [Overview](#overview)
- [Specifications Supported](#specifications-supported)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#-installation)
- [Getting Started](#getting-started)
- [API Overview](#-api-overview)
- [Security Support](#-security-support)
- [Error Handling](#-error-handling)
- [Testing](#-testing)
- [Example App](#example-app)
- [Migration Guide](#migration-guide)
- [Documentation](#documentation)
- [Library Implementations](#library-implementations-available-in)
- [Glossary](#glossary)

---

## Overview

The VCI Client library is a ready-to-integrate wallet-side solution for credential issuance. It takes care of the complexity behind OID4VCI — including issuer metadata discovery, PKCE-managed authorization, proof JWT construction, and credential download — enabling faster integration with less engineering effort.

**Key Responsibilities:**

* **VCI Client Library**

   * Handles OID4VCI protocol workflows and compliance
   * Manages PKCE session, authorization server discovery, and token exchange
   * Supports both OID4VCI 1.0 and draft 13 issuers transparently

* **Library Consumer (Wallet App)**

   * Owns user consent and credential rendering
   * Performs cryptographic proof signing
   * Implements authorization callbacks (web redirect / Presentation During Issuance)

> Consumer of this library is responsible for processing and rendering the credential after it is downloaded.

---

## Specifications Supported

The implementation follows:
- OpenID for Verifiable Credential Issuance 1.0
- OpenID for Verifiable Credential Issuance draft 13 compatibility for issuers that still expose the older metadata and request/response format

## Features

- Request credentials from OID4VCI-compliant credential issuers
- Supports both:
  - Issuer Initiated Flow (Credential Offer Flow).
  - Wallet Initiated Flow (Trusted Issuer Flow).
- Authorization server discovery for both flows
- PKCE-compliant OAuth 2.0 Authorization Code flow (RFC 7636)
  - PKCE session is managed internally by the library
- Pushed Authorization Requests (PAR) support (RFC 9126)
  - Used automatically when the authorization server advertises a `pushed_authorization_request_endpoint`
  - Falls back to a standard authorization request if the push fails and PAR is not mandated by the authorization server
- Well-defined **exception handling** with `VCI-XXX` error codes (see more on [this](#-error-handling))
- Support for multiple Credential formats:
  - `ldp_vc`
  - `mso_mdoc`
  - `vc+sd-jwt` / `dc+sd-jwt`

[//]: # (The reference for PDI  is intentionally pointing to kotlin library master branch to be release agnostic, as the PDI support is available for both kotlin and swift libraries. The documentation for PDI support is also common for both libraries, hence it is placed in the common doc folder in the root of the repository.)
- Presentation During Issuance (PDI) support for both download flows (For more details on PDI support, please refer to the [Presentation During Issuance documentation](https://github.com/inji/inji-vci-client/tree/master/doc/presentation-during-issuance-support.md))

## Requirements

- **Swift:** 5.7+
- **iOS:** 13.0+

---

## 📦 Installation

### Option 1: Add Using Xcode

1. Open your project in Xcode.
2. Navigate to **File > Add Package Dependencies...**.
3. Enter the repository URL:
   ```
   https://github.com/inji/inji-vci-client-ios-swift
   ```
4. Select the desired version and add it to your target.
5. Import in your Swift files:
   ```swift
   import VCIClient
   ```

### Option 2: Add Using `Package.swift`

```swift
dependencies: [
    .package(url: "https://github.com/inji/inji-vci-client-ios-swift", from: "1.0.0")
]
```

Then add `"VCIClient"` to your target's dependencies.

---

## Getting Started

### Typical Workflow

```
1. Initialise → VCIClient(traceabilityId:)
2. Discover   → getIssuerMetadata() / getCredentialConfigurationsSupported()
3. Download   → fetchCredentialsUsingCredentialOffer()   [issuer-initiated]
              → fetchCredentialsFromTrustedIssuer()      [wallet-initiated]
4. Render     → read credentialResponse.credentials ([CredentialItem])
```

### Quick Start Example

```swift
import VCIClient

let vciClient = VCIClient(traceabilityId: "wallet-app-101")

let credentialResponse = try await vciClient.fetchCredentialsUsingCredentialOffer(
    credentialOffer: deepLinkOrCredentialOfferURI,
    clientMetadata: ClientMetadata(clientId: "my-wallet", redirectUri: "https://my-wallet.example/callback"),
    authorizationMethods: [
        .redirectToWeb(openWebPage: { url in openBrowserAndReturnParams(url) })
    ],
    getTokenResponse: { tokenRequest in
        // Exchange authorization grant for access token
        return TokenResponse(accessToken: "...", cNonce: "...", tokenType: "Bearer", expiresIn: 3600, cNonceExpiresIn: 3600)
    },
    getProofs: { credentialIssuer, nonce, proofSigningAlgorithmsSupported in
        // Sign proof JWT and wrap it
        return CredentialRequestProofs(proofs: [buildAndSignProofJwt(nonce: nonce)])
    }
)

// credentialResponse.credentials is [CredentialItem]
for item in credentialResponse.credentials {
    renderCredential(item.credential) // item.credential is AnyCodable
}
```

> **Note:** The crypto implementations like signing the proof JWT are kept in your wallet app. The library handles OID4VCI protocol mechanics.

### Core Methods

| Method | Purpose | Returns |
|--------|---------|---------|
| `getIssuerMetadata(credentialIssuer:)` | Fetches raw issuer well-known metadata | `[String: Any]` |
| `getCredentialConfigurationsSupported(credentialIssuer:)` | Fetches supported credential configurations | `[String: Any]` |
| `fetchCredentialsUsingCredentialOffer(...)` | Downloads credentials via issuer-initiated (credential offer) flow | `CredentialResponse` |
| `fetchCredentialsFromTrustedIssuer(...)` | Downloads credentials via wallet-initiated (trusted issuer) flow | `CredentialResponse` |

---

## 🏗️ Construction of VCIClient instance

- The `VCIClient` is constructed with a `traceabilityId` which is used to track the session and traceability of the credential request.

```swift
let traceabilityId = "sample-trace-id"
let vciClient = VCIClient(traceabilityId: traceabilityId)
```

#### Parameters

| Name            | Type   | Required | Default Value | Description                          |
|-----------------|--------|----------|---------------|--------------------------------------|
| traceabilityId  | String | Yes      | N/A           | Unique identifier for the session    |

## 📖 API Overview

### 1. Obtain Issuer Metadata

Retrieve the issuer metadata from the credential issuer's well-known endpoint.

#### Parameters

| Name             | Type   | Required | Default Value | Description                  |
|------------------|--------|----------|---------------|------------------------------|
| credentialIssuer | String | Yes      | N/A           | URI of the Credential Issuer |

#### Returns

`[String: Any]` dictionary containing details like `credential_endpoint`, `credential_issuer`, and other issuer metadata from the well-known endpoint of Credential Issuer, which can be used by the consumer to display Issuer information, etc.

> Note: This method does not parse the metadata, it simply returns the raw Network response of well-known endpoint as a `[String: Any]`.

#### Example Usage

```swift
let issuerMetadata: [String: Any] = try await vciClient.getIssuerMetadata(credentialIssuer: "https://example.com/issuer")
    
//the response looks similar to this
[String: Any] = [
    "credential_issuer": "https://example.com/issuer",
    "credential_endpoint": "https://example.com/issuer/credential"
]
```

### 2. Obtain Credential Configurations Supported

Retrieve credential configurations supported for given issuer from its well-known endpoint.

#### Parameters

| Name             | Type   | Required | Default Value | Description                  |
|------------------|--------|----------|---------------|------------------------------|
| credentialIssuer | String | Yes      | N/A           | URI of the Credential Issuer |

#### Returns
Map of `credential_configurations_supported` objects containing details like `format`, `scope` and other configuration
information from the well-known endpoint of Credential Issuer, which can be used by the consumer to display supported
credential types, etc.

> Note: This method does not parse the metadata, it simply returns the raw Network response of well-known endpoint as a `[String: Any]`.

#### Example Usage

```swift
let credentialConfigurationsSupported : [String: Any] = try await vciClient.getCredentialConfigurationsSupported(
    credentialIssuer: "https://example.com/issuer"
)

//The response looks similar to this
[String: Any] = [
    "credentialConfigId-1": [
        "format": "ldp_vc",
        "credential_definition": [
            "type": ["VerifiableCredential", "ExampleCredential"]
        ]
    ],
    "credentialConfigId-2": [
        "format": "mso_mdoc",
        "doctype": "org.iso.18013.5.1.mDL"
    ],
    "credentialConfigId-3": [
        "format": "jwt_vc_json",
        "credential_definition": [
            "type": ["VerifiableCredential", "ExampleJwtCredential"],
        ],
        "scope": "ExampleJwtCredential"
    ]
]
```

### 3. Request Credential

Version `1.0.0` exposes two public credential download APIs:

- `fetchCredentialsUsingCredentialOffer(...)` for issuer-initiated flows
- `fetchCredentialsFromTrustedIssuer(...)` for wallet-initiated flows

Both methods use the OpenID4VCI 1.0-facing proof callback and return a normalized plural response. When an issuer still behaves like Draft-13, the library keeps the compatibility routing internal and still returns the 1.0 response shape.

### 3.1 Request Credential using Credential Offer

#### fetchCredentialsUsingCredentialOffer

- Method: `fetchCredentialsUsingCredentialOffer`
- This method allows you to fetch credential(s) using a credential offer, which can be either an embedded JSON or a URI pointing to the credential offer.
- It supports both **Pre-Authorization** and **Authorization** flows.
- The library handles the PKCE flow internally.
- User-trust based credential download supported through `onCheckIssuerTrust` callback.
- This method is the recommended way to request credential using credential offer.

##### Parameters

| Name                    | Type                          | Required | Default Value | Description                                                                                                                                                            |
|-------------------------|-------------------------------|----------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialOffer         | String                        | Yes      | N/A           | Credential offer as embedded JSON or `credential_offer_uri`                                                                                                            |
| clientMetadata          | ClientMetadata                | Yes      | N/A           | Contains client ID and redirect URI                                                                                                                                    |
| getTxCode               | TxCodeCallback                | No       | N/A           | Optional callback for TX Code in pre-authorized flows                                                                                                                  |
| authorizationMethods    | [AuthorizationMethod]         | Yes      | N/A           | Supported authorization callbacks for interactive flows [see authorization details](#authorizations)                                                                   |
| getTokenResponse        | TokenResponseCallback         | Yes      | N/A           | Callback that exchanges the authorization grant for an access token                                                                                                    |
| getProofs               | ProofsCallback                | Yes      | N/A           | Callback that prepares the proof set for the credential request, returning a `CredentialRequestProofs`                                                                 |
| onCheckIssuerTrust      | CheckIssuerTrustCallback      | No       | nil           | Optional callback to confirm that the issuer is trusted                                                                                                                |
| downloadTimeoutInMillis | Int64                         | No       | 10000         | Timeout for the credential request to the issuer                                                                                                                       |

##### Returns

An instance of `CredentialResponse` containing:

| Name                      | Type             | Description                                                                                                |
|---------------------------|------------------|------------------------------------------------------------------------------------------------------------|
| credentials               | [CredentialItem] | The credential(s) downloaded from the Issuer. Each `CredentialItem` exposes a `credential` (`AnyCodable`)  |
| credentialConfigurationId | String           | The identifier of the respective supported credential from well-known response                             |
| credentialIssuer          | String           | URI of the Credential Issuer                                                                               |

##### Example usage

```swift
let credentialResponse = try await vciClient.fetchCredentialsUsingCredentialOffer(
    credentialOffer: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fsample-issuer.com%2Fcredential-offer",
    clientMetadata: ClientMetadata(clientId: "sample-client-id", redirectUri: "https://sample-wallet.com/callback"),
    getTxCode: { inputMode, description, length in
        "sampleTxCode"
    },
    authorizationMethods: [
        .presentationDuringIssuance(
            selectCredentialsForPresentation: selectCredentialsForPresentationCallback(),
            signVerifiablePresentation: signVerifiablePresentationCallback()
        ),
        .redirectToWeb(openWebPage: openWebPageCallback())
    ],
    getTokenResponse: { tokenRequest in
        TokenResponse(
            accessToken: "sampleAccessToken",
            cNonce: "sampleNonce",
            tokenType: "Bearer",
            expiresIn: 3600,
            cNonceExpiresIn: 3600
        )
    },
    getProofs: { credentialIssuer, nonce, proofSigningAlgorithmsSupported in
        CredentialRequestProofs(proofs: ["sampleProofJwt"])
    },
    onCheckIssuerTrust: { credentialIssuer, issuerDisplay in
        true
    },
    downloadTimeoutInMillis: 10_000
)

credentialResponse.credentials // [CredentialItem]; each item's `credential` is an AnyCodable
credentialResponse.credentialConfigurationId // eg - "DriversLicense"
credentialResponse.credentialIssuer // eg - "https://sample-issuer.com"
```

### 3.2 Request Credential from Trusted Issuer

#### fetchCredentialsFromTrustedIssuer

- Method: `fetchCredentialsFromTrustedIssuer`
- It supports **Authorization** flow.
- The library handles the PKCE flow internally.

#### Parameters

| Name                      | Type                       | Required | Default Value | Description                                                                                                                                                            |
|---------------------------|----------------------------|----------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialIssuer          | String                     | Yes      | N/A           | URI of the credential issuer                                                                                                                                           |
| credentialConfigurationId | String                     | Yes      | N/A           | Identifier of the supported credential configuration                                                                                                                  |
| clientMetadata            | ClientMetadata             | Yes      | N/A           | Contains client ID and redirect URI                                                                                                                                    |
| authorizationMethods      | [AuthorizationMethod]      | Yes      | N/A           | Supported authorization callbacks for interactive flows [see authorization details](#authorizations)                                                                   |
| getTokenResponse          | TokenResponseCallback      | Yes      | N/A           | Callback that exchanges the authorization grant for an access token                                                                                                    |
| getProofs                 | ProofsCallback             | Yes      | N/A           | Callback that prepares the proof set for the credential request, returning a `CredentialRequestProofs`                                                                 |
| downloadTimeoutInMillis   | Int64                      | No       | 10000         | Timeout for the credential request to the issuer                                                                                                                       |

#### Returns

An instance of `CredentialResponse` containing:

| Name                      | Type             | Description                                                                                                |
|---------------------------|------------------|------------------------------------------------------------------------------------------------------------|
| credentials               | [CredentialItem] | The credential(s) downloaded from the Issuer. Each `CredentialItem` exposes a `credential` (`AnyCodable`)  |
| credentialConfigurationId | String           | The identifier of the respective supported credential from well-known response                             |
| credentialIssuer          | String           | URI of the Credential Issuer                                                                               |

#### Example usage

```swift
let credentialResponse = try await vciClient.fetchCredentialsFromTrustedIssuer(
    credentialIssuer: "https://sample-issuer.com",
    credentialConfigurationId: "DriversLicense",
    clientMetadata: ClientMetadata(
        clientId: "sample-client-id",
        redirectUri: "https://sample-wallet.com/callback"
    ),
    authorizationMethods: [
        .presentationDuringIssuance(
            selectCredentialsForPresentation: selectCredentialsForPresentationCallback(),
            signVerifiablePresentation: signVerifiablePresentationCallback()
        ),
        .redirectToWeb(openWebPage: openWebPageCallback())
    ],
    getTokenResponse: { tokenRequest in
        TokenResponse(
            accessToken: "sampleAccessToken",
            cNonce: "sampleNonce",
            tokenType: "Bearer",
            expiresIn: 3600,
            cNonceExpiresIn: 3600
        )
    },
    getProofs: { credentialIssuer, nonce, proofSigningAlgorithmsSupported in
        CredentialRequestProofs(proofs: ["sampleProofJwt"])
    },
    downloadTimeoutInMillis: 10_000
)

credentialResponse.credentials // [CredentialItem]; each item's `credential` is an AnyCodable
credentialResponse.credentialConfigurationId // eg - "DriversLicense"
credentialResponse.credentialIssuer // eg - "https://sample-issuer.com"
```

##### Authorizations

The `authorizationMethods` parameter is a list of supported wallet authorization flows. The library currently supports two authorization flows - _Redirect To Web_ and _Presentation During Issuance_.

1. Redirect To Web (for Authorization flow)

Redirect the user to the authorization endpoint in a web view or browser and return the authorization response parameters after successful authorization.

**Parameters :**

| Name        | Type                | Required | Default Value | Description                                                                                                                                                                         |
|-------------|---------------------|----------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| openWebPage | OpenWebPageCallback | Yes      | N/A           | Callback that opens the authorization endpoint and returns the authorization response parameters such as `code` and `state`                                                         |

**Example usage**
```swift
AuthorizationMethod.redirectToWeb(
    openWebPage: { authorizationEndpoint in
        let result: [String: Any] = openWebViewAndGetResult(authorizationEndpoint)
        return result
    }
)
```
> Note: The Redirect to Web flow for an interactive authorization flow is exposed as an experimental API, and is expected to be improved in future releases.

2. Presentation During Issuance

Presentation During Issuance allows the wallet to present a verifiable presentation to the credential issuer during the issuance flow, which can be used by the issuer to verify certain claims about the user before issuing the credential. The authorization for the download here is presentation of another credential (or a verifiable presentation) instead of user interaction-based authorization as in Redirect To Web flow.

###### Specification Reference

This implementation follows - [OpenID4VCI v1.1 Specification Commit](https://github.com/openid/OpenID4VCI/blob/31636e9bb7f0eef6933175e1e41c78ce79a69783/1.1/openid-4-verifiable-credential-issuance-1_1.md)

> Note:
> - While this library primarily implements OpenID4VCI 1.0 and draft 13, the Presentation During Issuance feature follows the v1.1 specification as mentioned above.
> - For Presentation During Issuance, this library internally uses [inji-openid4vp-ios-swift](https://github.com/inji/inji-openid4vp-ios-swift) to construct the VP and handle the presentation exchange with the issuer.
> 
> The OpenID4VP request is expected to follow either:
>
> * the [**Digital Credentials Query Language (DCQL)**](https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-1_0-wg-draft.html#name-digital-credentials-query-l) request format, as defined in the OpenID4VP specification V1.0, or
> * the [**DIF Presentation Exchange**](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#name-dif-presentation-exchange-2) request format, as defined in the Draft 23 OpenID4VP specification.


###### Supported Response Modes

The following response modes are supported:

1. `iar_post`
2. `iar_post.jwt`


**Parameters :**

| Name                             | Type                                     | Required    | Default Value  | Description                                                                                                                                        |
|----------------------------------|------------------------------------------|-------------|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| jsonLdCanonicalizer              | JsonLdCanonicalizerCallback              | Conditional | nil            | **Required only if supporting `ldp_vc` format** to canonicalize JSON-LD data for proof generation during VP construction<br/>. Otherwise Optional. |
| openid4vpWalletConfig            | WalletConfig                             | No          | WalletConfig() | Wallet's OpenID4VP related configuration                                                                                                           |
| selectCredentialsForPresentation | SelectCredentialsForPresentationCallback | Yes         | N/A            | Callback to select credentials from the wallet for the issuer's presentation request                                                               |
| signVerifiablePresentation       | SignVerifiablePresentationCallback       | Yes         | N/A            | Callback to sign the payload used for verifiable presentation construction                                                                         |



**Example usage**
```swift
AuthorizationMethod.presentationDuringIssuance(
    jsonLdCanonicalizer = jsonLdCanonicalizerCallback,
    openid4vpWalletConfig = openid4vpWalletConfig,
    selectCredentialsForPresentation: { presentationRequest in
        let selectedCredentials: [String: [Credential]] = selectCredentials(presentationRequest)
        return selectedCredentials
    },
    signVerifiablePresentation: { payload in
        let signedData: [VPTokenSigningResult] = signDataForVP(payload)
        return signedData
    }
)
```

[//]: # (The branch in inji-wallet for pdi docs link is pointed to master intentionally to ensure that the latest documentation is always referred.)
> For more details on the Presentation During Issuance flow and the expected implementation of the callbacks, please refer to the [inji-wallet Presentation During Issuance documentation](https://github.com/inji/inji-wallet/blob/master/docs/presentation-during-issuance-support.md)

---

## 🔐 Security Support

-  **PKCE (Proof Key for Code Exchange)** handled internally (RFC 7636)
-  Supports `S256` code challenge method
-  Secure `c_nonce` binding via proof JWTs

---

## 🛑 Error Handling

All exceptions thrown by the library are subclasses of `VCIClientException`.  
They carry structured fields that help consumers identify whether the failure came from the library itself, a wrapped library exception, or an upstream server response.

### `VCIClientException` fields

| Field                     | Type      | Meaning |
|---------------------------|-----------|---------|
| `code`                    | `String`  | The library-defined `VCI-*` error code. When the exception wraps another `VCIClientException`, `code` carries the **root** code resolved from the cause chain; otherwise it is the exception's own code. |
| `message`                 | `String`  | Human-readable summary of the failure, ready for logging or diagnostics. |
| `issuerErrorCode`         | `String?` | The issuer or authorization server `error` value when the remote service returned a structured OAuth/OID4VCI style error response. |
| `issuerErrorDescription`  | `String?` | The upstream `error_description` value when available. If the response body is not parseable JSON, the raw response body may be propagated here for diagnostics. |

### Structured error handling

The error model exposes the following fields so consumers can react precisely to failures:

- `code` identifies the root library failure. When an exception wraps another library exception, `code` resolves to the deepest `VCI-*` code in the cause chain rather than the wrapper's own code.
- `issuerErrorCode` captures the upstream server `error` field when present.
- `issuerErrorDescription` captures the upstream `error_description`, or the raw error body when structured parsing is not possible.

This means consumers can distinguish between:

- the original underlying library failure (surfaced through `code` even across wrapping),
- and a server-originated error payload returned by the issuer or authorization server.

#### Recommendations for consumers

- If your integration only switches on `code`, it will continue to work — and `code` now reflects the root failure category even when the exception is wrapped at the API boundary.
- If you want to infer server-side failures, use `issuerErrorCode` and `issuerErrorDescription` rather than parsing `message`.
- If you want better observability, log all three fields: `code`, `issuerErrorCode`, and `issuerErrorDescription`.
- If you want better retry and UX decisions, use `code` for the top-level category and `issuerErrorCode` for server-specific remediation.

### What each field means for consumers

- Use `code` for primary client-side branching, telemetry dimensions, and product analytics. It identifies the root library failure even when the exception is wrapped.
- Use `issuerErrorCode` to decide whether a failure is recoverable through user action, such as re-authentication, retry, or correcting a request.
- Use `issuerErrorDescription` for logs, support tooling, and developer diagnostics. Avoid showing it directly to end users without sanitization because it may contain server-specific text.

Some public API methods may wrap an internal `VCIClientException` into another `VCIClientException` before rethrowing it. This improves consistency at the API boundary without losing the root cause.

Example:

- `getIssuerMetadata()` may wrap the failure at the API boundary, but `code` still resolves to `VCI-009` when the underlying failure was an issuer metadata fetch error.
- `issuerErrorCode` may contain a remote value such as `invalid_token` if the upstream endpoint returned it.

### Recommended consumer handling

```swift
do {
    let credentialResponse = try await vciClient.fetchCredentialsUsingCredentialOffer(
        credentialOffer: credentialOffer,
        clientMetadata: clientMetadata,
        getTxCode: getTxCode,
        authorizationMethods: authorizationMethods,
        getTokenResponse: getTokenResponse,
        getProofs: getProofs
    )
} catch let error as VCIClientException {
    logger.error(
        "VCI request failed. code=\(error.code), " +
        "issuerCode=\(error.issuerErrorCode ?? "nil"), issuerDescription=\(error.issuerErrorDescription ?? "nil"), " +
        "message=\(error.message)"
    )

    switch error.code {
    case "VCI-007":
        showRetryMessage()
    case "VCI-003":
        triggerTokenRefresh()
    case "VCI-011":
        showAuthorizationFailure()
    default:
        showGenericFailure()
    }
}
```

### Error code reference

| Code    | Exception Type                          | Description                                                                                               |
|---------|-----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| VCI-001 | `AuthorizationServerDiscoveryException` | Failed to discover authorization server                                                                   |
| VCI-002 | `DownloadFailedException`               | Failed to download credential                                                                             |
| VCI-003 | `InvalidAccessTokenException`           | Access token is invalid                                                                                   |
| VCI-004 | `InvalidDataProvidedException`          | Required details not provided                                                                             |
| VCI-005 | `InvalidPublicKeyException`             | Invalid public key passed                                                                                 |
| VCI-006 | `NetworkRequestFailedException`         | Network request failed                                                                                    |
| VCI-007 | `NetworkRequestTimeoutException`        | Network request timed-out                                                                                 |
| VCI-008 | `CredentialOfferFetchFailedException`   | Failed to fetch credential offer                                                                          |
| VCI-009 | `IssuerMetadataFetchException`          | Failed to fetch issuerMetadata                                                                            |
| VCI-010 | `VCIClientException`                    | Generic API-boundary wrapper or unknown exception surfaced by `VCIClient` public methods                  |
| VCI-011 | `InteractiveAuthorizationException`     | Failed to perform Interactive authorization (Presentation During Issuance / Redirect to Web interaction)  |
| VCI-012 | `IllegalArgumentException`              | Invalid or missing argument in a request or response payload                                              |
| VCI-013 | `DPoPException`                         | Failed to generate or apply DPoP proof (RFC 9449)                                                         |
| VCI-014 | `PushedAuthorizationRequestException`   | Failed to push authorization request (RFC 9126)                                                           |

---

## 🧪 Testing

Mock-based tests are available covering:

- Credential download flow (offer + trusted issuer)
- Proof JWT signing callbacks
- Token exchange logic

> See `VCIClientTests` for full coverage

## Documentation

- Architecture decisions are documented in the [INJI VCI Client ADR directory](https://github.com/inji/inji-vci-client/tree/master/doc/adr).
- Documentation of the features are available in the [INJI VCI Client docs directory](https://github.com/inji/inji-vci-client/tree/master/doc).
- The OpenID4VCI 1.0 migration and Draft-13 compatibility design for this Swift library is documented in [ADR-0001](docs/adr/0001-openid4vci-v1-migration.md).

**Note: The Android library is available in the [INJI VCI Client repository](https://github.com/inji/inji-vci-client).**

---

## Library Implementations Available In

This library is officially supported and available in both Kotlin and Swift, ensuring seamless integration across Android and iOS platforms:

* [Kotlin](https://github.com/inji/inji-vci-client/tree/master/kotlin)
* [Swift](.)

---

## Example App

A complete sample app demonstrating credential issuance flows, proof JWT signing, and error handling with `VCIClient` is available here:

[Example iOS App Repository](./SwiftExample)

- Shows both **Credential Offer** and **Trusted Issuer** flows
- Includes best practices for callbacks and UI integration
- Can be built and run on iOS device only

> Use the example app to quickly get started and see the library in action.

---

## Migration Guide

For information on upgrading between versions, see the [Migration Guide](docs/migration-guides/MIGRATION_0.7.0_TO_1.0.0.md).

---

## Glossary

* **Credential:** A verifiable piece of information issued by a trusted issuer that can be presented to a verifier.
* **Verifiable Credential (VC):** A tamper-evident credential with cryptographic proofs of its authenticity and integrity.
* **Holder / Wallet:** The entity that owns Verifiable Credentials and presents them. This library provides the OID4VCI handling for wallet applications.
* **Credential Issuer:** A server that issues credentials to wallets following the OID4VCI protocol.
* **OID4VCI:** OpenID for Verifiable Credential Issuance. A standard protocol for issuing Verifiable Credentials to wallets.
* **Credential Offer:** A URI or JSON payload sent by the issuer to initiate the credential download flow.
* **Trusted Issuer:** A wallet-initiated flow where the wallet already knows the issuer and requests a credential directly.
* **PKCE:** Proof Key for Code Exchange (RFC 7636). A security extension to OAuth 2.0 that prevents authorization code interception.
* **c_nonce:** A nonce provided by the issuer to be bound into the proof JWT, ensuring the proof is fresh and tied to this issuance session.
* **Proof JWT:** A signed JWT included in the credential request to prove the wallet controls the key associated with the credential subject.
* **PDI (Presentation During Issuance):** An authorization flow where the wallet presents an existing credential to the issuer as proof of identity, instead of using a web redirect.
* **JWT:** JSON Web Token. A digitally signed token format used for secure transmission of claims.
* **AnyCodable:** A Swift type-erased `Codable` wrapper used to represent the credential payload, which may be a JSON object, string, or other format depending on the credential type.

