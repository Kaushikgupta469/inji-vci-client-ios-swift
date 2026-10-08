import Foundation

struct NetworkResponse {
    let body: String
    let headers: [AnyHashable: Any]?
}

class NetworkManager {
    static let shared = NetworkManager()

    func sendRequest(
        url: String,
        method: HttpMethod,
        headers: [String: String]? = nil,
        bodyParams: [String: String]? = nil,
        timeoutMillis: Int64 = Constants.defaultNetworkTimeoutInMillis
    ) async throws -> NetworkResponse {
        guard let requestURL = URL(string: url) else {
            throw NetworkRequestFailedException("Invalid URL: \(url)")
        }
        guard requestURL.scheme?.lowercased() == "https" else {
            throw NetworkRequestFailedException("Plaintext HTTP endpoints are not allowed; use HTTPS for: \(url)")
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = method.rawValue
        request.timeoutInterval = TimeInterval(timeoutMillis) / 1000

        headers?.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        if method == .post, let params = bodyParams {
            if headers?[Header.contentType.rawValue] == ContentTypes.applicationFormUrlEncoded.rawValue {
                let bodyString = params
                    .map { "\($0.key.formURLEncoded())=\($0.value.formURLEncoded())" }
                    .joined(separator: "&")

                request.httpBody = bodyString.data(using: .utf8)
            } else {
                let jsonData = try JSONEncoder().encode(bodyParams)
                request.httpBody = jsonData
            }
        }

        return try await sendRequest(request: request)
    }

    func sendRawRequest(
        url: String,
        method: HttpMethod,
        headers: [String: String]? = nil,
        body: Data? = nil,
        timeoutMillis: Int64 = Constants.defaultNetworkTimeoutInMillis
    ) async throws -> NetworkResponse {
        guard let requestURL = URL(string: url) else {
            throw NetworkRequestFailedException("Invalid URL: \(url)")
        }
        guard requestURL.scheme?.lowercased() == "https" else {
            throw NetworkRequestFailedException("Plaintext HTTP endpoints are not allowed; use HTTPS for: \(url)")
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = method.rawValue
        request.timeoutInterval = TimeInterval(timeoutMillis) / 1000

        headers?.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        if method == .post {
            request.httpBody = body
        }

        return try await sendRequest(request: request)
    }

    func sendRequest(request: URLRequest) async throws -> NetworkResponse {
        guard request.url?.scheme?.lowercased() == "https" else {
            throw NetworkRequestFailedException(
                "Plaintext HTTP endpoints are not allowed; use HTTPS for: \(request.url?.absoluteString ?? "unknown")"
            )
        }
        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw NetworkRequestFailedException("Invalid response")
            }

            let body = String(data: data, encoding: .utf8) ?? ""

            guard (200 ... 299).contains(httpResponse.statusCode) else {
                let (issuerErrorCode, issuerErrorDescription) =
                    parseServerErrorResponse(body)

                throw NetworkRequestFailedException(
                    message: "HTTP \(httpResponse.statusCode)",
                    httpStatusCode: httpResponse.statusCode,
                    headers: httpResponse.allHeaderFields,
                    issuerErrorCode: issuerErrorCode,
                    issuerErrorDescription: issuerErrorDescription
                )
            }

            return NetworkResponse(
                body: body,
                headers: httpResponse.allHeaderFields
            )

        } catch let error as URLError where error.code == .timedOut {
            throw NetworkRequestTimeoutException(
                message: error.localizedDescription,
                cause: error
            )
        } catch let error as NetworkRequestFailedException {
            throw error
        } catch {
            throw NetworkRequestFailedException(
                message: error.localizedDescription,
                cause: error
            )
        }
    }

    private func parseServerErrorResponse(_ body: String) -> (String?, String?) {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return (nil, body)
        }

        let errorCode = json["error"] as? String
        let errorDescription = json["error_description"] as? String

        return (errorCode, errorDescription)
    }
}
