import Foundation

/// Reads the n, e and d integers from a PKCS#1 `RSAPrivateKey` DER (SEQUENCE of version, n, e, d, ...)
/// as exported by `SecKeyCopyExternalRepresentation`, so the DPoP RSA path can rebuild the key from
/// components rather than via `CryptoSwift.RSA(rawRepresentation:)`, whose ASN.1 decoder intermittently
/// rejects valid Apple exports containing a leading-zero DER integer (krzyzanowskim/CryptoSwift#892).
enum RSAKeyDER {

    static func privateComponents(_ der: Data) throws -> (n: [UInt8], e: [UInt8], d: [UInt8]) {
        let bytes = [UInt8](der)
        var cursor = 0

        func fail() -> DPoPException {
            DPoPException("Unable to parse RSA private key DER")
        }

        func readLength() throws -> Int {
            guard cursor < bytes.count else { throw fail() }
            var length = Int(bytes[cursor]); cursor += 1
            guard length & 0x80 != 0 else { return length }
            let byteCount = length & 0x7f
            guard byteCount > 0, byteCount <= 8, cursor + byteCount <= bytes.count else { throw fail() }
            length = 0
            for _ in 0..<byteCount {
                length = (length << 8) | Int(bytes[cursor]); cursor += 1
            }
            return length
        }

        func readInteger() throws -> [UInt8] {
            guard cursor < bytes.count, bytes[cursor] == 0x02 else { throw fail() }
            cursor += 1
            let length = try readLength()
            guard length > 0, cursor + length <= bytes.count else { throw fail() }
            let value = Array(bytes[cursor..<cursor + length])
            cursor += length
            return value
        }

        // Descend into the outer SEQUENCE, then read its integers positionally.
        guard cursor < bytes.count, bytes[cursor] == 0x30 else { throw fail() }
        cursor += 1
        _ = try readLength()
        _ = try readInteger()      // version
        let n = try readInteger()
        let e = try readInteger()
        let d = try readInteger()
        return (n: n, e: e, d: d)
    }
}
