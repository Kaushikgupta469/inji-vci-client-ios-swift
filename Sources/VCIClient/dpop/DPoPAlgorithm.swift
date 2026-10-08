import CryptoSwift
import Foundation
import JSONWebAlgorithms
import JSONWebKey
import Security

private let rsaKeySizeInBits = 2048

struct DPoPKeyMaterial {
    let signingKey: any KeyRepresentable
    let publicJWK: JWK
}

enum DPoPAlgorithm: String {
    case eddsa = "EdDSA"
    case es256k = "ES256K"
    case es256 = "ES256"
    case es384 = "ES384"
    case es512 = "ES512"
    case rs256 = "RS256"

    var signingAlgorithm: SigningAlgorithm {
        switch self {
        case .eddsa: return .EdDSA
        case .es256k: return .ES256K
        case .es256: return .ES256
        case .es384: return .ES384
        case .es512: return .ES512
        case .rs256: return .RS256
        }
    }

    func generateKeyMaterial() throws -> DPoPKeyMaterial {
        switch self {
        case .rs256:
            return try generateRsaKeyMaterial()
        default:
            return try generateEcKeyMaterial()
        }
    }

    private func generateEcKeyMaterial() throws -> DPoPKeyMaterial {
        let (keyType, curve) = ellipticParameters()
        guard let generator = JWK(keyType: keyType, curve: curve).keyGeneration else {
            throw DPoPException("Unable to generate a DPoP key for algorithm \(rawValue)")
        }
        let privateKey = try generator.generateKeyPairJWK(purpose: .signing)
        return DPoPKeyMaterial(
            signingKey: privateKey,
            publicJWK: DPoPAlgorithm.publicOnly(privateKey)
        )
    }

    private func generateRsaKeyMaterial() throws -> DPoPKeyMaterial {
        // SecKeyCreateRandomKey is hardware-accelerated, far faster than
        // pure-Swift prime generation in CryptoSwift.RSA(keySize:).
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: rsaKeySizeInBits
        ]
        var genError: Unmanaged<CFError>?
        guard let privateSecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
            throw DPoPException("RSA key generation failed: \(genError!.takeRetainedValue())")
        }
        var exportError: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(privateSecKey, &exportError) as Data? else {
            throw DPoPException("RSA key export failed: \(exportError!.takeRetainedValue())")
        }
        // Build from parsed components rather than RSA(rawRepresentation:); see RSAKeyDER.
        let components = try RSAKeyDER.privateComponents(keyData)
        let privateKey = CryptoSwift.RSA(n: components.n, e: components.e, d: components.d)
        let fullJWK = privateKey.jwkRepresentation
        guard let n = fullJWK.n, let e = fullJWK.e else {
            throw DPoPException("Unable to extract RSA public key components")
        }
        return DPoPKeyMaterial(signingKey: privateKey, publicJWK: JWK(keyType: .rsa, e: e, n: n))
    }

    private func ellipticParameters() -> (JWK.KeyType, JWK.CryptographicCurve) {
        switch self {
        case .eddsa: return (.octetKeyPair, .ed25519)
        case .es256k: return (.ellipticCurve, .secp256k1)
        case .es384: return (.ellipticCurve, .p384)
        case .es512: return (.ellipticCurve, .p521)
        default: return (.ellipticCurve, .p256)
        }
    }

    private static func publicOnly(_ jwk: JWK) -> JWK {
        JWK(keyType: jwk.keyType, curve: jwk.curve, x: jwk.x, y: jwk.y)
    }

    /// Selects the best DPoP signing algorithm advertised by the authorization server.
    ///
    /// Preference order:
    ///  1. EdDSA  (ed)       – Edwards-curve; smallest signatures, modern
    ///  2. ES256K (eck1)     – ECDSA secp256k1; widely deployed
    ///  3. ES256  (ecr1)     – ECDSA secp256r1 (P-256); default fallback
    ///  4. ES384, ES512      – Other EC r1 variants (P-384, P-521)
    ///  5. RS256  (rsa)      – RSA; last resort, large key/signature size
    static func select(_ authorizationServerSupported: [String]?) throws -> DPoPAlgorithm {
        guard let supported = authorizationServerSupported, !supported.isEmpty else {
            return .es256
        }
        let preferenceOrder: [DPoPAlgorithm] = [.eddsa, .es256k, .es256, .es384, .es512, .rs256]
        guard let match = preferenceOrder.first(where: { supported.contains($0.rawValue) }) else {
            let clientSupported = preferenceOrder.map(\.rawValue).joined(separator: ", ")
            throw DPoPException(
                "No supported DPoP algorithm found. AS supports: \(supported), " +
                "client supports: [\(clientSupported)]"
            )
        }
        return match
    }
}
