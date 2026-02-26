import Foundation
import Security
import Sodium
import VCIClient

class VCIClientWrapper {
    static let shared = VCIClientWrapper()
    private let sodium = Sodium()

    private init() {}

    
    func startCredentialOfferFlow(from scanned: String, onResult: @escaping (String) -> Void) {
        Task {
            do {
                let client = VCIClient(traceabilityId: "demo-trace-id")

                let credentialResponse = try await client.requestCredentialByCredentialOffer(
                    credentialOffer: scanned,
                    clientMetadata: ClientMetadata(clientId: "wallet", redirectUri: "https://sampleApp"),
                    getTxCode: nil,
                    authorizeUser: { _ in
                        "dummy-auth-code"
                    },
                    getTokenResponse: { tokenRequest in try await self.exchangeToken(tokenRequest, proxy: false) },
                    getProofJwt: { credentialIssuer, cNonce, proofSigningAlgorithmsSupported in
                        self.signProofJWT(
                            cNonce: cNonce,
                            issuer: credentialIssuer,
                            isTrustedIssuer: false,
                            proofSigningAlgorithmsSupported: proofSigningAlgorithmsSupported
                        )
                    }
                )

                if let vc = try credentialResponse?.toJsonString() {
                    onResult("✅ Credential Issued:\n\(vc)")
                } else {
                    onResult("❌ No credential received")
                }
            } catch {
                onResult("❌ Error: \(error.localizedDescription)")
            }
        }
    }

    func startTrustedIssuerFlow(from uri: String, onResult: @escaping (String) -> Void) {
        Task {
            do {
                let client = VCIClient(traceabilityId: "demo-trace-id")

                let credentialResponse = try await client.requestCredentialFromTrustedIssuer(
                    credentialIssuer: credentialIssuer ,
                    credentialConfigurationId: credentialConfigurationId,
                    clientMetadata: ClientMetadata(clientId: clientId, redirectUri: redirectUri),
                    authorizeUser: { authEndpoint in
                        await withCheckedContinuation { continuation in
                            DispatchQueue.main.async {
                                NotificationCenter.default.post(name: Notification.Name("ShowAuthWebView"), object: authEndpoint)
                            }

                            var observer: NSObjectProtocol?
                            observer = NotificationCenter.default.addObserver(forName: Notification.Name("AuthCodeReceived"), object: nil, queue: .main) { notification in
                                if let code = notification.object as? String {
                                    if let obs = observer {
                                        NotificationCenter.default.removeObserver(obs)
                                    }

                                    continuation.resume(returning: code)
                                }
                            }
                        }
                    },
                    getTokenResponse: { tokenRequest in try await self.exchangeToken(tokenRequest, proxy: true) },
                    getProofJwt: { credentialIssuer, cNonce, proofSigningAlgorithmsSupported in
                        self.signProofJWT(
                            cNonce: cNonce,
                            issuer: credentialIssuer,
                            isTrustedIssuer: true,
                            proofSigningAlgorithmsSupported: proofSigningAlgorithmsSupported
                        )
                    })

                if let vc = try credentialResponse?.toJsonString() {
                    onResult("✅ Credential Issued:\n\(vc)")
                } else {
                    onResult("Downloading VC")
                }
            } catch {
                onResult("❌ Trusted Issuer Error: \(error.localizedDescription)")
            }
        }
    }

    func startMdlTrustedIssuerFlow(onResult: @escaping (String) -> Void) {
        Task {
            do {
                let client = VCIClient(traceabilityId: "demo-mdl-trace-id")
                
                print("[MDL-FLOW] Starting MDL Trusted Issuer Flow")
                print("[MDL-FLOW] Credential Issuer: \(mdlCredentialIssuer)")
                print("[MDL-FLOW] Credential Configuration ID: \(mdlCredentialConfigurationId)")
                
                let credentialResponse = try await client.requestCredentialFromTrustedIssuer(
                    credentialIssuer: mdlCredentialIssuer,
                    credentialConfigurationId: mdlCredentialConfigurationId,
                    clientMetadata: ClientMetadata(clientId: mdlClientId, redirectUri: mdlRedirectUri),
                    authorizeUser: { authEndpoint in
                        await withCheckedContinuation { continuation in
                            DispatchQueue.main.async {
                                NotificationCenter.default.post(name: Notification.Name("ShowAuthWebView"), object: authEndpoint)
                            }
                            
                            var observer: NSObjectProtocol?
                            observer = NotificationCenter.default.addObserver(forName: Notification.Name("AuthCodeReceived"), object: nil, queue: .main) { notification in
                                if let code = notification.object as? String {
                                    if let obs = observer {
                                        NotificationCenter.default.removeObserver(obs)
                                    }
                                    continuation.resume(returning: code)
                                }
                            }
                        }
                    },
                    getTokenResponse: { tokenRequest in try await self.exchangeToken(tokenRequest, proxyEndpoint: mdlProxyTokenEndpoint) },
                    getProofJwt: { credentialIssuer, cNonce, proofSigningAlgorithmsSupported in
                        print("[MDL-FLOW] Signing proof JWT with algorithms supported: \(proofSigningAlgorithmsSupported)")
                        return self.signProofJWT(
                            cNonce: cNonce,
                            issuer: credentialIssuer,
                            isTrustedIssuer: true,
                            proofSigningAlgorithmsSupported: proofSigningAlgorithmsSupported
                        )
                    })
                
                if let vc = try credentialResponse?.toJsonString() {
                    onResult("✅ MDL Credential Issued:\n\(vc)")
                } else {
                    onResult("⏳ Downloading MDL VC...")
                }
            } catch {
                onResult("❌ MDL Error: \(error.localizedDescription)")
            }
        }
    }

    func fetchCredentialTypes(
        from credentialIssuer: String,
        onResult: @escaping (_ rawJson: String, _ keys: [String]) -> Void
    ) {
        Task {
            do {
                let client = VCIClient(traceabilityId: "demo-trace-id")
                let types = try await client.getCredentialConfigurationsSupported(credentialIssuer: credentialIssuer)

                let rawJson = try types.toJsonString()
                let keys = Array(types.keys)

                onResult(rawJson, keys)
            } catch {
                onResult("❌ Error: \(error.localizedDescription)", [])
            }
        }
    }

    private func signProofJWT(
        cNonce: String?,
        issuer: String,
        isTrustedIssuer: Bool?,
        proofSigningAlgorithmsSupported: [String] = []
    ) -> String {
        let useES256 = proofSigningAlgorithmsSupported.contains("ES256")
        
        print("[PROOF-JWT] Supported algorithms: \(proofSigningAlgorithmsSupported)")
        print("[PROOF-JWT] Using algorithm: \(useES256 ? "ES256 (EC P-256)" : "EdDSA (Ed25519)")")
        
        if useES256 {
            return signProofJWTWithEC(cNonce: cNonce, issuer: issuer)
        } else {
            return signProofJWTWithEd25519(cNonce: cNonce, issuer: issuer, isTrustedIssuer: isTrustedIssuer)
        }
    }

    private func signProofJWTWithEd25519(cNonce: String?, issuer: String, isTrustedIssuer: Bool?) -> String {
        guard let keyPair = sodium.sign.keyPair() else {
            fatalError("❌ Failed to generate Ed25519 key pair")
        }

        let publicKeyJwk: [String: Any] = [
            "kty": "OKP",
            "crv": "Ed25519",
            "x": Data(keyPair.publicKey).base64URLEncodedString(),
        ]

        let publicKeyJwkData = try! JSONSerialization.data(withJSONObject: publicKeyJwk)
        let kid = "did:jwk:" + publicKeyJwkData.base64URLEncodedString() + "#0"
        let alg = isTrustedIssuer == true ? "Ed25519" : "EdDSA"
        let header: [String: Any] = [
            "alg": alg,
            "typ": "openid4vci-proof+jwt",
            "kid": kid,
        ]

        let now = Int(Date().timeIntervalSince1970)

        var payload: [String: Any] = [
            "aud": issuer,
            "iat": now,
            "exp": now + 18000,
        ]
        if let nonce = cNonce {
            payload["nonce"] = nonce
        }

        let headerData = try! JSONSerialization.data(withJSONObject: header)
        let payloadData = try! JSONSerialization.data(withJSONObject: payload)

        let headerBase64 = headerData.base64URLEncodedString()
        let payloadBase64 = payloadData.base64URLEncodedString()

        let signingInput = "\(headerBase64).\(payloadBase64)"
        let signingBytes = Array(signingInput.utf8)

        guard let signature = sodium.sign.signature(message: signingBytes, secretKey: keyPair.secretKey) else {
            fatalError("❌ Failed to sign JWT")
        }

        let signatureBase64 = Data(signature).base64URLEncodedString()
        
        let jwt = "\(signingInput).\(signatureBase64)"
        print("[PROOF-JWT] Ed25519 JWT header: \(String(data: headerData, encoding: .utf8) ?? "")")
        return jwt
    }

    private func signProofJWTWithEC(cNonce: String?, issuer: String) -> String {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("❌ Failed to generate EC P-256 key pair: \(error!.takeRetainedValue())")
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            fatalError("❌ Failed to extract public key from EC key pair")
        }

        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            fatalError("❌ Failed to export public key: \(exportError!.takeRetainedValue())")
        }

        let xData = publicKeyData[1..<33]
        let yData = publicKeyData[33..<65]

        let publicKeyJwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": xData.base64URLEncodedString(),
            "y": yData.base64URLEncodedString()
        ]
        
        let publicKeyJwkData = try! JSONSerialization.data(withJSONObject: publicKeyJwk, options: .sortedKeys)
        let kid = "did:jwk:" + publicKeyJwkData.base64URLEncodedString() + "#0"

        let header: [String: Any] = [
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": kid
        ]

        let now = Int(Date().timeIntervalSince1970)
        var payload: [String: Any] = [
            "aud": issuer,
            "iat": now,
            "exp": now + 18000,
        ]
        if let nonce = cNonce {
            payload["nonce"] = nonce
        }

        let headerData = try! JSONSerialization.data(withJSONObject: header, options: .sortedKeys)
        let payloadData = try! JSONSerialization.data(withJSONObject: payload, options: .sortedKeys)
        
        let headerBase64 = headerData.base64URLEncodedString()
        let payloadBase64 = payloadData.base64URLEncodedString()
        
        let signingInput = "\(headerBase64).\(payloadBase64)"
        let signingInputData = signingInput.data(using: .utf8)!

        var signError: Unmanaged<CFError>?
        guard let derSignature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            signingInputData as CFData,
            &signError
        ) as Data? else {
            fatalError("❌ Failed to sign JWT with EC key: \(signError!.takeRetainedValue())")
        }

        let rawSignature = derToRawECDSASignature(derSignature)
        let signatureBase64 = rawSignature.base64URLEncodedString()
        
        let jwt = "\(signingInput).\(signatureBase64)"
        print("[PROOF-JWT] ES256 JWT header: \(String(data: headerData, encoding: .utf8) ?? "")")
        print("[PROOF-JWT] ES256 JWT public key JWK: \(String(data: publicKeyJwkData, encoding: .utf8) ?? "")")
        return jwt
    }

    private func derToRawECDSASignature(_ derData: Data) -> Data {
        let bytes = [UInt8](derData)
        var index = 0

        guard bytes[index] == 0x30 else { fatalError("Invalid DER signature") }
        index += 1
        if bytes[index] & 0x80 != 0 {
            let lenBytes = Int(bytes[index] & 0x7F)
            index += 1 + lenBytes
        } else {
            index += 1
        }
        
        guard bytes[index] == 0x02 else { fatalError("Invalid DER signature") }
        index += 1
        let rLen = Int(bytes[index])
        index += 1
        var rBytes = Array(bytes[index..<(index + rLen)])
        index += rLen
        
        guard bytes[index] == 0x02 else { fatalError("Invalid DER signature") }
        index += 1
        let sLen = Int(bytes[index])
        index += 1
        var sBytes = Array(bytes[index..<(index + sLen)])

        if rBytes.count == 33 && rBytes[0] == 0x00 { rBytes.removeFirst() }
        if sBytes.count == 33 && sBytes[0] == 0x00 { sBytes.removeFirst() }

        while rBytes.count < 32 { rBytes.insert(0x00, at: 0) }
        while sBytes.count < 32 { sBytes.insert(0x00, at: 0) }
        
        return Data(rBytes + sBytes)
    }

    private func exchangeToken(_ req: TokenRequest, proxy: Bool) async throws -> TokenResponse {
        let endpoint = proxy ? proxyTokenEndpoint : req.tokenEndpoint
        return try await exchangeToken(req, proxyEndpoint: endpoint)
    }
    
    private func exchangeToken(_ req: TokenRequest, proxyEndpoint: String) async throws -> TokenResponse {
        var items: [URLQueryItem] = [
            URLQueryItem(name: "grant_type", value: req.grantType.rawValue),
        ]
        if let code = req.authCode { items.append(URLQueryItem(name: "code", value: code)) }
        if let codeVerifier = req.codeVerifier { items.append(URLQueryItem(name: "code_verifier", value: codeVerifier)) }
        if let pac = req.preAuthCode { items.append(URLQueryItem(name: "pre-authorized_code", value: pac)) }
        if let tx = req.txCode { items.append(URLQueryItem(name: "tx_code", value: tx)) }
        if let clientId = req.clientId { items.append(URLQueryItem(name: "client_id", value: clientId)) }
        if let redirectUri = req.redirectUri { items.append(URLQueryItem(name: "redirect_uri", value: redirectUri)) }
        guard let url = URL(string: proxyEndpoint) else {
            throw NSError(domain: "VCIClientWrapper", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid token endpoint"])
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = formURLEncode(items: items).data(using: .utf8)

        let (data, resp) = try await URLSession.shared.data(for: request)
        guard let http = resp as? HTTPURLResponse, (200 ..< 300).contains(http.statusCode) else {
            let txt = String(data: data, encoding: .utf8) ?? "<no body>"
            throw NSError(domain: "VCIClientWrapper",
                          code: (resp as? HTTPURLResponse)?.statusCode ?? -1,
                          userInfo: [NSLocalizedDescriptionKey: "Token error: \(txt)"])
        }
        let decoder = JSONDecoder()
        return try decoder.decode(TokenResponse.self, from: data)
    }

    private func formURLEncode(items: [URLQueryItem]) -> String {
        items.map { qi in
            let k = qi.name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? qi.name
            let v = (qi.value ?? "").addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
            return "\(k)=\(v)"
        }.joined(separator: "&")
    }
}

extension Data {
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension Array where Element == UInt8 {
    var data: Data { return Data(self) }
}

extension Dictionary where Key == String, Value == Any {
    func toJsonString(pretty: Bool = true) throws -> String {
        let options: JSONSerialization.WritingOptions = pretty ? .prettyPrinted : []
        let data = try JSONSerialization.data(withJSONObject: self, options: options)
        return String(data: data, encoding: .utf8) ?? "{}"
    }
}
