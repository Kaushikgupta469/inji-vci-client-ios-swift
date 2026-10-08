# Migration Guide: inji-vci-client-ios-swift 0.7.0 → 1.0.0

This guide helps Swift developers upgrade from **`inji-vci-client-ios-swift` 0.7.0** to **1.0.0**.

Scope: **breaking changes in the public API** — `VCIClient` class, its credential download methods, and the Presentation During Issuance (PDI) authorization callbacks.

Note:
- The core flow and concepts remain the same, but method names, the proof callback, the credential response model, and the PDI callback signatures have changed to align with the final OpenID4VCI 1.0 specification.

---

## Quick flow overview

1. `VCIClient(traceabilityId:)` initialises the client for the session.
2. `getIssuerMetadata(credentialIssuer:)` fetches issuer well-known metadata.
3. `getCredentialConfigurationsSupported(credentialIssuer:)` fetches supported credential configurations.
4. `fetchCredentialsUsingCredentialOffer(...)` (issuer-initiated) or `fetchCredentialsFromTrustedIssuer(...)` (wallet-initiated) downloads credentials and returns a `CredentialResponse`.
5. Your wallet reads `credentialResponse.credentials` — a `[CredentialItem]` list — and renders each item.

---

## Feature overview

1. **0.7.0**
   1. Supported OID4VCI draft 13.
   2. Credential download methods returned a single `credential: AnyCodable`.
   3. Proof callback accepted one nonce and returned a single JWT string.

2. **1.0.0**
   1. Supports OID4VCI **1.0** with retained draft 13 backward compatibility — the library auto-detects the issuer's spec version from its metadata.
   2. Credential download methods return a `credentials: [CredentialItem]` list, matching the OID4VCI 1.0 response shape.
   3. Proof callback returns a `CredentialRequestProofs` object, supporting one or more proofs per request.
   4. **PDI `selectCredentialsForPresentation` callback** now returns `[String: [Credential]]` instead of `[String: [FormatType: [Any]]]`.
   5. **PDI `signVerifiablePresentation` callback** now returns `[VPTokenSigningResult]` instead of `[VPTokenSigningResultV2]`.
   6. **PDI gains two new optional parameters**: `jsonLdCanonicalizer` (required for `ldp_vc` format) and `openid4vpWalletConfig`.
   7. **PDI response modes updated**: `iar_post` / `iar_post.jwt` are the supported response modes.
   8. Issuer metadata fetch now validates that `credential_issuer` in the well-known response matches the requested issuer [OID4VCI §12.2.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.1).
   9. `VCIClientException` carries structured upstream error fields (`issuerErrorCode`, `issuerErrorDescription`).
   10. Legacy low-level APIs (`requestCredential`, `requestCredentialByCredentialOffer`, `requestCredentialFromTrustedIssuer`) have been removed.

---

## TL;DR (what you must change)

1. **Rename credential offer method**
   - **0.7.0**: `fetchCredentialUsingCredentialOffer(...)`
   - **1.0.0**: `fetchCredentialsUsingCredentialOffer(...)` (plural *Credentials*)

2. **Rename trusted issuer method**
   - **0.7.0**: `fetchCredentialFromTrustedIssuer(...)`
   - **1.0.0**: `fetchCredentialsFromTrustedIssuer(...)` (plural *Credentials*)

3. **Replace `getProofJwt` callback with `getProofs`**
   - **0.7.0**: `getProofJwt: (credentialIssuer, cNonce, proofSigningAlgorithmsSupported) -> String`
   - **1.0.0**: `getProofs: (credentialIssuer, nonce, proofSigningAlgorithmsSupported) -> CredentialRequestProofs`

4. **Update credential response access**
   - **0.7.0**: `credentialResponse?.credential` (`AnyCodable`)
   - **1.0.0**: `credentialResponse.credentials` (`[CredentialItem]`); access each via `item.credential`

5. **Update PDI callbacks** — `selectCredentialsForPresentation` now returns `[String: [Credential]]` (not `[String: [FormatType: [Any]]]`); `signVerifiablePresentation` now returns `[VPTokenSigningResult]` (not `[VPTokenSigningResultV2]`).

6. **Add new PDI parameters if needed** — `jsonLdCanonicalizer` is now required when using `ldp_vc` format in PDI; `openid4vpWalletConfig` is available as an optional configuration.

7. **Update PDI response mode handling** — use `iar_post` / `iar_post.jwt` response modes.

8. **Remove any calls to deleted APIs** — `requestCredential`, `requestCredentialByCredentialOffer`, and `requestCredentialFromTrustedIssuer` are gone; migrate to the `fetchCredentials*` methods.

9. **Update error handling** — `VCIClientException` now exposes `issuerErrorCode` and `issuerErrorDescription` alongside `code` and `message`.

---

## Before vs After: credential offer download

### 0.7.0 (old)

```swift
let credentialResponse: CredentialResponse? = try await vciClient.fetchCredentialUsingCredentialOffer(
    credentialOffer: "openid-credential-offer://?credential_offer_uri=...",
    clientMetadata: ClientMetadata(clientId: "sample-client-id", redirectUri: "https://sample-wallet.com/callback"),
    getTxCode: { inputMode, description, length in
        "sampleTxCode"
    },
    authorizationMethods: [
        .presentationDuringIssuance(
            selectCredentialsForPresentation: { vpRequest in
                try await selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation: { unsignedVPTokens in
                try await signVerifiablePresentationCallback(unsignedVPTokens: unsignedVPTokens)
            },
            ldpVpSignatureSuite: "Ed25519Signature2020"
        ),
        .redirectToWeb(openWebPage: openWebPageCallback())
    ],
    getTokenResponse: { tokenRequest in
        TokenResponse(accessToken: "sampleAccessToken", cNonce: "sampleNonce",
                      tokenType: "Bearer", expiresIn: 3600, cNonceExpiresIn: 3600)
    },
    getProofJwt: { credentialIssuer, cNonce, proofSigningAlgorithmsSupported in
        // Sign JWT and return the compact serialization
        "sampleProofJwt"
    },
    onCheckIssuerTrust: { credentialIssuer, issuerDisplay in true },
    downloadTimeoutInMillis: 10_000
)

credentialResponse?.credential           // AnyCodable — the single downloaded credential
credentialResponse?.credentialConfigurationId
credentialResponse?.credentialIssuer
```

### 1.0.0 (new)

```swift
let credentialResponse = try await vciClient.fetchCredentialsUsingCredentialOffer(
    credentialOffer: "openid-credential-offer://?credential_offer_uri=...",
    clientMetadata: ClientMetadata(clientId: "sample-client-id", redirectUri: "https://sample-wallet.com/callback"),
    getTxCode: { inputMode, description, length in
        "sampleTxCode"
    },
    authorizationMethods: [
        .presentationDuringIssuance(
            selectCredentialsForPresentation: { vpRequest in
                try await selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation: { unsignedVPTokens in
                try await signVerifiablePresentationCallback(unsignedVPTokens: unsignedVPTokens)
            }
        ),
        .redirectToWeb(openWebPage: openWebPageCallback())
    ],
    getTokenResponse: { tokenRequest in
        TokenResponse(accessToken: "sampleAccessToken", cNonce: "sampleNonce",
                      tokenType: "Bearer", expiresIn: 3600, cNonceExpiresIn: 3600)
    },
    getProofs: { credentialIssuer, nonce, proofSigningAlgorithmsSupported in
        // Sign JWT(s) and wrap in CredentialRequestProofs
        CredentialRequestProofs(proofs: ["sampleProofJwt"])
    },
    onCheckIssuerTrust: { credentialIssuer, issuerDisplay in true },
    downloadTimeoutInMillis: 10_000
)

credentialResponse.credentials            // [CredentialItem] — list of downloaded credentials
credentialResponse.credentials.first?.credential  // AnyCodable of the first credential
credentialResponse.credentialConfigurationId
credentialResponse.credentialIssuer
```

### Parameter mapping

| 0.7.0 parameter                                                                                                                               | 1.0.0 parameter             | Migration note                                                                |
|-----------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|-------------------------------------------------------------------------------|
| `getProofJwt: ProofJwtCallback`                                                                                                               | `getProofs: ProofsCallback` | Return a `CredentialRequestProofs(proofs: [...])` instead of a plain `String` |
| `credentialOffer`, `clientMetadata`, `getTxCode`, `authorizationMethods`, `getTokenResponse`, `onCheckIssuerTrust`, `downloadTimeoutInMillis` | _(unchanged)_               | Same parameter names and types                                                |

### Response mapping

| 0.7.0 field                          | 1.0.0 field                         | Migration note                                                                |
|--------------------------------------|-------------------------------------|-------------------------------------------------------------------------------|
| `credential: AnyCodable`             | `credentials: [CredentialItem]`     | Iterate `credentials`; each `CredentialItem` exposes `credential: AnyCodable` |
| `credentialConfigurationId: String?` | `credentialConfigurationId: String` | No longer optional                                                            |
| `credentialIssuer: String?`          | `credentialIssuer: String`          | No longer optional                                                            |

---

## Before vs After: trusted issuer download

### 0.7.0 (old)

```swift
let credentialResponse: CredentialResponse? = try await vciClient.fetchCredentialFromTrustedIssuer(
    credentialIssuer: "https://sample-issuer.com",
    credentialConfigurationId: "DriversLicense",
    clientMetadata: ClientMetadata(clientId: "sample-client-id", redirectUri: "https://sample-wallet.com/callback"),
    authorizationMethods: [
        .presentationDuringIssuance(
            selectCredentialsForPresentation: { vpRequest in
                try await selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation: { unsignedVPTokens in
                try await signVerifiablePresentationCallback(unsignedVPTokens: unsignedVPTokens)
            },
            ldpVpSignatureSuite: "Ed25519Signature2020"
        ),
        .redirectToWeb(openWebPage: openWebPageCallback())
    ],
    getTokenResponse: { tokenRequest in
        TokenResponse(accessToken: "sampleAccessToken", cNonce: "sampleNonce",
                      tokenType: "Bearer", expiresIn: 3600, cNonceExpiresIn: 3600)
    },
    getProofJwt: { credentialIssuer, cNonce, proofSigningAlgorithmsSupported in
        "sampleProofJwt"
    },
    downloadTimeoutInMillis: 10_000
)

credentialResponse?.credential
credentialResponse?.credentialConfigurationId
credentialResponse?.credentialIssuer
```

### 1.0.0 (new)

```swift
let credentialResponse = try await vciClient.fetchCredentialsFromTrustedIssuer(
    credentialIssuer: "https://sample-issuer.com",
    credentialConfigurationId: "DriversLicense",
    clientMetadata: ClientMetadata(clientId: "sample-client-id", redirectUri: "https://sample-wallet.com/callback"),
    authorizationMethods: [
        .presentationDuringIssuance(
            selectCredentialsForPresentation: { vpRequest in
                try await selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation: { unsignedVPTokens in
                try await signVerifiablePresentationCallback(unsignedVPTokens: unsignedVPTokens)
            }
        ),
        .redirectToWeb(openWebPage: openWebPageCallback())
    ],
    getTokenResponse: { tokenRequest in
        TokenResponse(accessToken: "sampleAccessToken", cNonce: "sampleNonce",
                      tokenType: "Bearer", expiresIn: 3600, cNonceExpiresIn: 3600)
    },
    getProofs: { credentialIssuer, nonce, proofSigningAlgorithmsSupported in
        CredentialRequestProofs(proofs: ["sampleProofJwt"])
    },
    downloadTimeoutInMillis: 10_000
)

credentialResponse.credentials
credentialResponse.credentialConfigurationId
credentialResponse.credentialIssuer
```

The parameter and response mapping is the same as described in the credential offer section above.

---

## Before vs After: Presentation During Issuance (PDI) callbacks

### What stays the same

- `AuthorizationMethod.presentationDuringIssuance(...)` is still the way to pass PDI into both download methods.
- `selectCredentialsForPresentation` and `signVerifiablePresentation` callbacks are still required.

### What changes in practice

1. **`selectCredentialsForPresentation` return type changed**
   - **0.7.0**: returned `[String: [FormatType: [Any]]]`
   - **1.0.0**: returns `[String: [Credential]]` — a flat list of `Credential` objects per input descriptor ID /Credential query ID

2. **`signVerifiablePresentation` callback inputs and return changed**
   - **0.7.0**: Input: `[UnsignedVPTokenV2]`
   - **1.0.0**: Input: `[UnsignedVPToken]` (adds the `id` property in addition to `format`, `holderKeyReference`, `signatureAlgorithm`, and `dataToSign`)

   - **0.7.0**: Returns: `[VPTokenSigningResultV2]`
   - **1.0.0**: Returns: `[VPTokenSigningResult]` (adds the `id` property in addition to `signedData`)

3. **Two new optional parameters added**
   - `jsonLdCanonicalizer` — **required when your wallet issues `ldp_vc` format credentials during PDI**; optional otherwise
   - `openid4vpWalletConfig` — optional OpenID4VP wallet configuration (trusted verifiers, supported formats, etc.)

4. **Response modes updated**
   - `iar_post` and `iar_post.jwt` are the supported response modes in 1.0.0

### 0.7.0 PDI usage (old)

```swift
AuthorizationMethod.presentationDuringIssuance(
    selectCredentialsForPresentation: { presentationRequest in
        // 0.7.0: returned [String: [FormatType: [Any]]]
        let selectedCredentials: [String: [FormatType: [Any]]] = selectCredentials(presentationRequest)
        return selectedCredentials
    },
    signVerifiablePresentation: { payload in
        // 0.7.0: payload items are [UnsignedVPTokenV2]; return [VPTokenSigningResultV2]
        let signedData: [VPTokenSigningResultV2] = signDataForVP(payload)
        return signedData
    },
    ldpVpSignatureSuite: "Ed25519Signature2020"
)
```

### 1.0.0 PDI usage (new)

```swift
AuthorizationMethod.presentationDuringIssuance(
    jsonLdCanonicalizer: { data in
        // Required only for ldp_vc — canonicalize JSON-LD and return base64url-encoded hash
        return canonicalizeAndHash(data)
    },
    openid4vpWalletConfig: WalletConfig(), // Optional — use defaults or pass your config
    selectCredentialsForPresentation: { presentationRequest in
        // 1.0.0: return [String: [Credential]] — flat list per descriptor/query ID
        let selectedCredentials: [String: [Credential]] = selectCredentials(presentationRequest)
        return selectedCredentials
    },
    signVerifiablePresentation: { payload in
        // 1.0.0: payload items are [UnsignedVPToken]; return [VPTokenSigningResult]
        let signedData: [VPTokenSigningResult] = signDataForVP(payload)
        return signedData
    }
)
```

### Parameter mapping

| 0.7.0 parameter                    | 1.0.0 parameter                    | Change                                                                          |
|------------------------------------|------------------------------------|---------------------------------------------------------------------------------|
| _(not present)_                    | `jsonLdCanonicalizer`              | **New** — required for `ldp_vc`, optional otherwise                             |
| _(not present)_                    | `openid4vpWalletConfig`            | **New** — optional OpenID4VP wallet config                                      |
| `selectCredentialsForPresentation` | `selectCredentialsForPresentation` | Return type changed: `[String: [FormatType: [Any]]]` → `[String: [Credential]]` |
| `signVerifiablePresentation`       | `signVerifiablePresentation`       | Return type changed: `[VPTokenSigningResultV2]` → `[VPTokenSigningResult]`      |
| `ldpVpSignatureSuite`              | (not present)                      | Removed                                                                         |

---

## Before vs After: error handling

### What stays the same

- All exceptions are subclasses of `VCIClientException`.
- `code` (`VCI-*`) and `message` continue to work as before.

### New in 1.0.0

Two structured fields are now available on `VCIClientException`:

| New field                | Type      | Meaning                                                                                                        |
|--------------------------|-----------|----------------------------------------------------------------------------------------------------------------|
| `issuerErrorCode`        | `String?` | The `error` value returned by the issuer or authorization server in a structured OAuth/OID4VCI error response. |
| `issuerErrorDescription` | `String?` | The `error_description` from the upstream server, or the raw body when structured parsing is not possible.     |

Additionally, `code` now resolves to the **root** error code across the cause chain — if an exception wraps another `VCIClientException`, `code` carries the deepest `VCI-*` code rather than the wrapper's own code.

### 0.7.0 error handling (old)

```swift
do {
    let credentialResponse = try await vciClient.fetchCredentialUsingCredentialOffer(...)
} catch let error as VCIClientException {
    switch error.code {
    case "VCI-007": showRetryMessage()
    default: showGenericFailure(error.message)
    }
}
```

### 1.0.0 error handling (new)

```swift
do {
    let credentialResponse = try await vciClient.fetchCredentialsUsingCredentialOffer(...)
} catch let error as VCIClientException {
    logger.error(
        "VCI request failed. code=\(error.code), " +
        "issuerCode=\(error.issuerErrorCode ?? "nil"), " +
        "issuerDescription=\(error.issuerErrorDescription != nil ? "<redacted>" : "nil"), " +
        "message=\(error.message)"
    )

    switch error.code {
    case "VCI-007": showRetryMessage()
    case "VCI-003": triggerTokenRefresh()
    case "VCI-011": showAuthorizationFailure()
    default: showGenericFailure()
    }
}
```

---

## Removed and changed APIs

> **Notice**
>
> 1.0.0 retains the core `VCIClient` entry point but removes the legacy low-level methods deprecated since 0.7.0, and renames the two primary download methods.

### API changes

| 0.7.0                                                                    | 1.0.0 status      | Change                                                                                                                                        |
|--------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `fetchCredentialUsingCredentialOffer(...)`                               | **Renamed**       | Use `fetchCredentialsUsingCredentialOffer(...)`                                                                                               |
| `fetchCredentialFromTrustedIssuer(...)`                                  | **Renamed**       | Use `fetchCredentialsFromTrustedIssuer(...)`                                                                                                  |
| `getProofJwt` callback                                                   | **Replaced**      | Use `getProofs` returning `CredentialRequestProofs`                                                                                           |
| `CredentialResponse.credential: AnyCodable`                              | **Replaced**      | Use `CredentialResponse.credentials: [CredentialItem]`                                                                                        |
| PDI `selectCredentialsForPresentation` → `[String: [FormatType: [Any]]]` | **Changed**       | Now returns `[String: [Credential]]`                                                                                                          |
| PDI `signVerifiablePresentation`                                         | **Changed**       | Input changed from `UnsignedVPTokenV2` to `UnsignedVPToken`. Return type changed from `[VPTokenSigningResultV2]` to `[VPTokenSigningResult]`. |
| PDI _(no `jsonLdCanonicalizer`)_                                         | **New parameter** | Required for `ldp_vc`; optional otherwise                                                                                                     |
| PDI _(no `openid4vpWalletConfig`)_                                       | **New parameter** | Optional OpenID4VP wallet configuration                                                                                                       |

### APIs removed in 1.0.0

| Removed method                            | Deprecated since | Replacement                                                                             |
|-------------------------------------------|------------------|-----------------------------------------------------------------------------------------|
| `requestCredentialByCredentialOffer(...)` | 0.7.0            | `fetchCredentialsUsingCredentialOffer(...)`                                             |
| `requestCredentialFromTrustedIssuer(...)` | 0.7.0            | `fetchCredentialsFromTrustedIssuer(...)`                                                |
| `requestCredential(...)`                  | 0.7.0            | `fetchCredentialsUsingCredentialOffer(...)` or `fetchCredentialsFromTrustedIssuer(...)` |

### Unchanged APIs

The following public methods are unchanged in 1.0.0:

- `VCIClient(traceabilityId:)`
- `getIssuerMetadata(credentialIssuer:)`
- `getCredentialConfigurationsSupported(credentialIssuer:)`

---

## Minimal working Swift example in 1.0.0

```swift
import VCIClient

func downloadCredential(
    traceabilityId: String,
    credentialOffer: String,
    clientId: String,
    redirectUri: String
) async throws -> [CredentialItem] {

    let vciClient = VCIClient(traceabilityId: traceabilityId)

    let credentialResponse = try await vciClient.fetchCredentialsUsingCredentialOffer(
        credentialOffer: credentialOffer,
        clientMetadata: ClientMetadata(clientId: clientId, redirectUri: redirectUri),
        getTxCode: { inputMode, description, length in
            // Prompt user for transaction code if required
            return "userProvidedTxCode"
        },
        authorizationMethods: [
            .presentationDuringIssuance(
                selectCredentialsForPresentation: { presentationRequest in
                    // Return wallet credentials matching the presentation request
                    return [:]
                },
                signVerifiablePresentation: { payload in
                    // Sign VP payload; return [VPTokenSigningResult]
                    return []
                }
            ),
            .redirectToWeb(openWebPage: { authorizationEndpoint in
                // Open web view, complete authorization, return response params
                return [:]
            })
        ],
        getTokenResponse: { tokenRequest in
            // Exchange authorization grant for access token
            return TokenResponse(
                accessToken: "accessToken",
                cNonce: "nonce",
                tokenType: "Bearer",
                expiresIn: 3600,
                cNonceExpiresIn: 3600
            )
        },
        getProofs: { credentialIssuer, nonce, proofSigningAlgorithmsSupported in
            // Build and sign proof JWT(s) using nonce and supported algorithms
            let signedProofJwt = buildAndSignProofJwt(nonce: nonce, issuer: credentialIssuer)
            return CredentialRequestProofs(proofs: [signedProofJwt])
        },
        onCheckIssuerTrust: { credentialIssuer, issuerDisplay in
            // Return true if the issuer is trusted by the wallet
            return true
        },
        downloadTimeoutInMillis: 10_000
    )

    // credentialResponse.credentials is [CredentialItem]
    return credentialResponse.credentials
}

// Helpers (implement in your wallet app)

func buildAndSignProofJwt(nonce: String, issuer: String) -> String {
    // Build the proof JWT header/payload, sign with your holder key, and return the compact serialization
    return "eyJ..."
}
```

Notes:
- Replace stub callback bodies with your wallet's actual implementation.
- `getProofs` replaces the old `getProofJwt` — wrap your signed JWT in `CredentialRequestProofs(proofs: [...])`.
- Iterate `credentialResponse.credentials` to access each downloaded credential via `.credential` (`AnyCodable`).

---

## Appendix: Key Swift types and entry points

| Purpose                              | Type / File                                                             |
|--------------------------------------|-------------------------------------------------------------------------|
| Entry point                          | `VCIClient`                                                             |
| Credential download (offer)          | `fetchCredentialsUsingCredentialOffer(...)`                             |
| Credential download (trusted issuer) | `fetchCredentialsFromTrustedIssuer(...)`                                |
| Proof callback return type           | `CredentialRequestProofs`                                               |
| Credential response                  | `CredentialResponse`                                                    |
| Individual credential in response    | `CredentialItem`                                                        |
| Client registration details          | `ClientMetadata`                                                        |
| Token exchange response              | `TokenResponse`                                                         |
| Authorization flows                  | `AuthorizationMethod` (`.redirectToWeb`, `.presentationDuringIssuance`) |
| Exception base type                  | `VCIClientException`                                                    |
