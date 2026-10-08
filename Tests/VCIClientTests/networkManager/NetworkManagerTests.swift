@testable import VCIClient
import XCTest

final class NetworkManagerTests: XCTestCase {
    private func requestBodyData(from request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }

        guard let stream = request.httpBodyStream else {
            return nil
        }

        stream.open()
        defer { stream.close() }

        var data = Data()
        let bufferSize = 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            if read > 0 {
                data.append(buffer, count: read)
            } else {
                break
            }
        }

        return data
    }

    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }

    override func tearDown() {
        URLProtocol.unregisterClass(MockURLProtocol.self)
        MockURLProtocol.requestHandler = nil
        super.tearDown()
    }

    func testSendRequestSuccess() async throws {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!

            let data = #"{"status":"ok"}"#.data(using: .utf8)!

            return (response, data)
        }

        let response = try await NetworkManager.shared.sendRequest(
            url: "https://example.com",
            method: .get
        )

        XCTAssertEqual(response.body, #"{"status":"ok"}"#)
    }

    func testSendRequestInvalidURL() async {
        do {
            _ = try await NetworkManager.shared.sendRequest(
                url: "mock",
                method: .get
            )
            XCTFail("Expected invalid URL error")
        } catch {
            XCTAssertTrue(error is NetworkRequestFailedException)
        }
    }

    func testSendRequest_urlRequest_rejectsPlaintextHttp() async {
        let request = URLRequest(url: URL(string: "http://issuer.example.com/credential")!)
        do {
            _ = try await NetworkManager.shared.sendRequest(request: request)
            XCTFail("Expected plaintext HTTP to be rejected")
        } catch {
            XCTAssertTrue(error is NetworkRequestFailedException)
        }
    }

    func testSendRequest_urlRequest_allowsHttps() async throws {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data("{}".utf8))
        }

        let request = URLRequest(url: URL(string: "https://example.com/credential")!)
        let response = try await NetworkManager.shared.sendRequest(request: request)

        XCTAssertEqual(response.body, "{}")
    }

    func testSendRequestHTTPError() async {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 404,
                httpVersion: nil,
                headerFields: nil
            )!

            let data = "Not Found".data(using: .utf8)!

            return (response, data)
        }

        do {
            _ = try await NetworkManager.shared.sendRequest(
                url: "https://example.com",
                method: .get
            )
            XCTFail("Expected HTTP error")
        } catch {
            XCTAssertTrue(error is NetworkRequestFailedException)
        }
    }

    func testSendRequestTimeout() async {
        MockURLProtocol.requestHandler = { _ in
            throw URLError(.timedOut)
        }

        do {
            _ = try await NetworkManager.shared.sendRequest(
                url: "https://example.com",
                method: .get
            )
            XCTFail("Expected timeout error")
        } catch {
            XCTAssertTrue(error is NetworkRequestTimeoutException)
        }
    }

    func testSendRequest_postFormUrlEncoded_encodesBodyAndHeaders() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Content-Type"),
                "application/x-www-form-urlencoded"
            )
            let body = try XCTUnwrap(
                String(data: self.requestBodyData(from: request) ?? Data(), encoding: .utf8)
            )
            let params = Set(body.split(separator: "&").map(String.init))
            XCTAssertEqual(
                params,
                Set([
                    "name=John%20Doe",
                    "city=New%20York",
                ])
            )

            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["X-Test": "yes"]
            )!

            return (response, #"{"status":"ok"}"#.data(using: .utf8)!)
        }

        let response = try await NetworkManager.shared.sendRequest(
            url: "https://example.com/form",
            method: .post,
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            bodyParams: [
                "name": "John Doe",
                "city": "New York",
            ]
        )

        XCTAssertEqual(response.body, #"{"status":"ok"}"#)
        XCTAssertEqual(response.headers?["X-Test"] as? String, "yes")
    }

    func testSendRequest_postJson_encodesBodyAsJson() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "POST")

            let json = try XCTUnwrap(self.requestBodyData(from: request))
            let object = try XCTUnwrap(
                try JSONSerialization.jsonObject(with: json) as? [String: String]
            )

            XCTAssertEqual(object["scope"], "openid")
            XCTAssertEqual(object["grant_type"], "authorization_code")

            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!

            return (response, #"{"status":"ok"}"#.data(using: .utf8)!)
        }

        _ = try await NetworkManager.shared.sendRequest(
            url: "https://example.com/json",
            method: .post,
            headers: ["Content-Type": "application/json"],
            bodyParams: [
                "scope": "openid",
                "grant_type": "authorization_code",
            ]
        )
    }

    func testSendRequestV2_postAssignsRawBody() async throws {
        let expectedBody = Data("raw-body".utf8)

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(self.requestBodyData(from: request), expectedBody)

            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!

            return (response, #"{"status":"ok"}"#.data(using: .utf8)!)
        }

        _ = try await NetworkManager.shared.sendRawRequest(
            url: "https://example.com/raw",
            method: .post,
            body: expectedBody
        )
    }

    func testSendRequestV2_getDoesNotAssignBody() async throws {
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertNil(request.httpBody)

            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!

            return (response, Data())
        }

        _ = try await NetworkManager.shared.sendRawRequest(
            url: "https://example.com/raw",
            method: .get,
            body: Data("ignored".utf8)
        )
    }

    func testSendRequestHTTPError_parsesServerErrorPayload() async {
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 400,
                httpVersion: nil,
                headerFields: nil
            )!

            let data = #"{"error":"invalid_request","error_description":"missing proof"}"#.data(using: .utf8)!

            return (response, data)
        }

        do {
            _ = try await NetworkManager.shared.sendRequest(
                url: "https://example.com",
                method: .get
            )
            XCTFail("Expected HTTP error")
        } catch let error as NetworkRequestFailedException {
            XCTAssertEqual(error.issuerErrorCode, "invalid_request")
            XCTAssertEqual(error.issuerErrorDescription, "missing proof")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}

final class MockURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    static var lastRequest: URLRequest?

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        MockURLProtocol.lastRequest = request

        guard let handler = MockURLProtocol.requestHandler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        do {
            let (response, data) = try handler(request)

            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)

        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
