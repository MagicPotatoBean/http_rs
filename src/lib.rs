use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};
#[derive(Debug, Clone, Copy)]
pub struct HttpRequestConfig {
    pub max_method_len: usize,
    pub max_path_len: usize,
    pub max_protocol_len: usize,
    pub max_header_len: usize,
    pub max_body_len: usize,
    pub read_timeout: Duration,
}
impl Default for HttpRequestConfig {
    fn default() -> Self {
        Self {
            max_method_len: 10,
            max_path_len: 100,
            max_protocol_len: 10,
            max_header_len: 1000,
            max_body_len: 1 << 20,
            read_timeout: Duration::from_millis(50),
        }
    }
}
#[derive(Debug)]
pub struct HttpClient {
    pub incoming: HttpRequest,
    pub outgoing: Option<HttpResponse>,
    stream: TcpStream,
}
impl std::fmt::Display for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let incoming_string = format!("{}", self.incoming);
        let mut output = "\r\n* Start of packet\r\n".to_owned();
        for line in incoming_string.lines() {
            output.push_str("< ");
            output.push_str(line);
            output.push_str("\r\n");
        }
        let mut outgoing_string = "* No response sent".to_owned();
        if let Some(ref outgoing_packet) = self.outgoing {
            outgoing_string = format!("{}", outgoing_packet);
        }
        for line in outgoing_string.lines() {
            output.push_str("> ");
            output.push_str(line);
            output.push_str("\r\n");
        }
        output.push_str("* End of packet");
        write!(f, "{}", output)
    }
}
impl Eq for HttpClient {}
impl PartialEq for HttpClient {
    fn eq(&self, other: &Self) -> bool {
        self.incoming.eq(&other.incoming) && self.outgoing.eq(&other.outgoing)
    }
}
impl HttpClient {
    pub fn close(self) -> std::io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
    pub fn get_stream(&self) -> std::io::Result<TcpStream> {
        self.stream.try_clone()
    }
    pub fn new(
        mut stream: TcpStream,
        config: &HttpRequestConfig,
    ) -> Result<Self, ParseHttpRequestError> {
        Ok(Self {
            incoming: HttpRequest::new(&mut stream, config)?,
            outgoing: None,
            stream,
        })
    }
    pub fn get_request<'a>(&'a self) -> &'a HttpRequest {
        &self.incoming
    }
    pub fn respond(&mut self, response: HttpResponse) -> std::io::Result<()> {
        self.outgoing = Some(response.clone());
        self.stream.write_all(format!("{}", response).as_bytes())
    }
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HttpCode {
    // 1xx
    Continue,
    SwitchingProtocols,
    Processing,
    EarlyHints,
    // 2xx
    #[default]
    Ok,
    Created,
    Accepted,
    NonAuthoritativeInformation,
    NoContent,
    ResetContent,
    PartialContent,
    MultiStatus,
    AlreadyReported,
    IMUsed,
    // 3xx
    MultipleChoices,
    MovedPermanently,
    Found,
    SeeOther,
    NotModified,
    UseProxy,
    SwitchProxy,
    TemporaryRedirect,
    PermanentRedirect,
    // 4xx
    BadRequest,
    Unauthorised,
    PaymentRequired,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    ProxyAuthenticationRequired,
    RequestTimeout,
    Conflict,
    Gone,
    LengthRequired,
    PreconditionFailed,
    PayloadTooLarge,
    UriTooLong,
    UnsupportedMediaType,
    RangeNotSatisfiable,
    ExpectationFailed,
    ImATeapot,
    MisdirectedRequest,
    UnprocessableContent,
    Locked,
    FailedDependancy,
    TooEarly,
    UpgradeRequired,
    PreconditionRequired,
    TooManyRequests,
    RequestHeaderFieldsTooLarge,
    UnavailableForLegalReasons,
    // 5xx
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    HttpVersionNotSupported,
    VariantAlsoNegotiates,
    InsufficientStorage,
    LoopDetected,
    NotExtended,
    NetworkAuthenticationRequired,
}
impl std::fmt::Display for HttpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                // 1xx
                Self::Continue => 100,
                Self::SwitchingProtocols => 101,
                Self::Processing => 102,
                Self::EarlyHints => 103,
                // 2xx
                Self::Ok => 200,
                Self::Created => 201,
                Self::Accepted => 202,
                Self::NonAuthoritativeInformation => 203,
                Self::NoContent => 204,
                Self::ResetContent => 205,
                Self::PartialContent => 206,
                Self::MultiStatus => 207,
                Self::AlreadyReported => 208,
                Self::IMUsed => 226,
                // 3xx
                Self::MultipleChoices => 300,
                Self::MovedPermanently => 301,
                Self::Found => 302,
                Self::SeeOther => 303,
                Self::NotModified => 304,
                Self::UseProxy => 305,
                Self::SwitchProxy => 306,
                Self::TemporaryRedirect => 307,
                Self::PermanentRedirect => 308,
                // 4xx
                Self::BadRequest => 400,
                Self::Unauthorised => 401,
                Self::PaymentRequired => 402,
                Self::Forbidden => 403,
                Self::NotFound => 404,
                Self::MethodNotAllowed => 405,
                Self::NotAcceptable => 406,
                Self::ProxyAuthenticationRequired => 407,
                Self::RequestTimeout => 408,
                Self::Conflict => 409,
                Self::Gone => 410,
                Self::LengthRequired => 411,
                Self::PreconditionFailed => 412,
                Self::PayloadTooLarge => 413,
                Self::UriTooLong => 414,
                Self::UnsupportedMediaType => 415,
                Self::RangeNotSatisfiable => 416,
                Self::ExpectationFailed => 417,
                Self::ImATeapot => 418,
                Self::MisdirectedRequest => 421,
                Self::UnprocessableContent => 422,
                Self::Locked => 423,
                Self::FailedDependancy => 424,
                Self::TooEarly => 425,
                Self::UpgradeRequired => 426,
                Self::PreconditionRequired => 428,
                Self::TooManyRequests => 429,
                Self::RequestHeaderFieldsTooLarge => 431,
                Self::UnavailableForLegalReasons => 451,
                // 5xx
                Self::InternalServerError => 500,
                Self::NotImplemented => 501,
                Self::BadGateway => 502,
                Self::ServiceUnavailable => 503,
                Self::GatewayTimeout => 504,
                Self::HttpVersionNotSupported => 505,
                Self::VariantAlsoNegotiates => 506,
                Self::InsufficientStorage => 507,
                Self::LoopDetected => 508,
                Self::NotExtended => 510,
                Self::NetworkAuthenticationRequired => 511,
            }
        )
    }
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub code: HttpCode,
    pub message: String,
    pub protocol: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
impl std::fmt::Display for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}{}\r\n\r\n{}",
            self.protocol,
            self.code,
            self.message,
            format_headers(&self.headers),
            String::from_utf8_lossy(&self.body)
        )
    }
}
fn format_headers(map: &HashMap<String, String>) -> String {
    let mut fmt_headers = String::default();
    for (key, value) in map.iter() {
        fmt_headers.push_str(&format!("\r\n{key}: {value}"));
    }
    fmt_headers
}
impl HttpResponse {
    pub fn builder() -> HttpResponseBuilder {
        HttpResponseBuilder::new()
    }
}
#[derive(Debug, Default, Clone)]
pub struct HttpResponseBuilder {
    code: Option<HttpCode>,
    message: String,
    protocol: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}
impl HttpResponseBuilder {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn code(mut self, code: HttpCode) -> Self {
        self.code = Some(code);
        self
    }
    pub fn message<T>(mut self, message: T) -> Self
    where
        T: Into<String>,
    {
        self.message = message.into();
        self
    }
    pub fn protocol<T>(mut self, protocol: T) -> Self
    where
        T: Into<String>,
    {
        self.protocol = protocol.into();
        self
    }
    pub fn header<T, U>(mut self, key: T, value: U) -> Self
    where
        T: Into<String>,
        U: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }
    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.body = data;
        self
    }
    pub fn build(self) -> Result<HttpResponse, BuildHttpResponseError> {
        let Some(code) = self.code else {
            return Err(BuildHttpResponseError::MissingCode);
        };
        if self.message.len() == 0 {
            return Err(BuildHttpResponseError::MissingMessage);
        };
        if self.protocol.len() == 0 {
            return Err(BuildHttpResponseError::MissingProtocol);
        };
        Ok(HttpResponse {
            code,
            message: self.message,
            protocol: self.protocol,
            headers: self.headers,
            body: self.body,
        })
    }
}
#[derive(Debug, Clone, Copy)]
pub enum BuildHttpResponseError {
    MissingCode,
    MissingMessage,
    MissingProtocol,
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub path: String,
    pub method: HttpMethod,
    pub protocol: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
impl std::fmt::Display for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {} {}{}\r\n\r\n{}",
            self.method,
            self.path,
            self.protocol,
            format_headers(&self.headers),
            String::from_utf8_lossy(&self.body)
        )
    }
}
impl HttpRequest {
    fn new(
        stream: &mut TcpStream,
        config: &HttpRequestConfig,
    ) -> Result<Self, ParseHttpRequestError> {
        stream
            .set_read_timeout(Some(config.read_timeout))
            .ok()
            .ok_or(ParseHttpRequestError::CantSetTimeout)?;
        // Parse method
        let mut method = Vec::new();
        for index in 0..(1 + config.max_method_len) {
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte) {
                Ok(()) => {
                    method.push(byte[0]);
                    if method.ends_with(b" ") {
                        method = method[0..(method.len() - 1)].to_vec();
                        break;
                    } else if index == config.max_method_len {
                        return Err(ParseHttpRequestError::OversizedMethod);
                    }
                }
                Err(_) => return Err(ParseHttpRequestError::MissingOrIncompleteMethod),
            }
        }
        // Parse path
        let mut path = Vec::new();
        for index in 0..(1 + config.max_path_len) {
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte) {
                Ok(()) => {
                    path.push(byte[0]);
                    if path.ends_with(b" ") {
                        path = path[0..(path.len() - 1)].to_vec();
                        break;
                    } else if index == config.max_path_len {
                        return Err(ParseHttpRequestError::OversizedPath);
                    }
                }
                Err(_) => return Err(ParseHttpRequestError::MissingOrIncompletePath),
            }
        }
        // Parse protocol
        let mut protocol = Vec::new();
        for index in 0..(2 + config.max_protocol_len) {
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte) {
                Ok(()) => {
                    protocol.push(byte[0]);
                    if protocol.ends_with(b"\r\n") {
                        protocol = protocol[0..(protocol.len() - 2)].to_vec();
                        break;
                    } else if index == (config.max_protocol_len + 1) {
                        return Err(ParseHttpRequestError::OversizedProtocol);
                    }
                }
                Err(_) => return Err(ParseHttpRequestError::MissingOrIncompleteProtocol),
            }
        }
        // Parse headers
        let mut headers = Vec::new();
        for index in 0..(4 + config.max_header_len) {
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte) {
                Ok(()) => {
                    headers.push(byte[0]);
                    if headers.ends_with(b"\r\n\r\n") {
                        headers = headers[0..(headers.len() - 4)].to_vec();
                        break;
                    } else if index == config.max_header_len + 3 {
                        return Err(ParseHttpRequestError::OversizedHeaders);
                    }
                }
                Err(_) => break, // As 0 headers are allowed
            }
        }
        // Parse body
        let mut body = Vec::new();
        for index in 0..(1 + config.max_body_len) {
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte) {
                Ok(()) => {
                    body.push(byte[0]);
                    if index == config.max_body_len {
                        return Err(ParseHttpRequestError::OversizedBody);
                    }
                }
                Err(_) => break,
            }
        }
        let headers = String::from_utf8(headers)
            .ok()
            .ok_or(ParseHttpRequestError::InvalidUtf8)?;
        let mut header_map = HashMap::new();
        for line in headers.lines() {
            if let Some((key, value)) = line.split_once(": ") {
                header_map.insert(key.to_owned(), value.to_owned());
            } else if let Some((key, value)) = line.split_once(":") {
                header_map.insert(key.to_owned(), value.to_owned());
            }
        }
        let method = String::from_utf8(method)
            .ok()
            .ok_or(ParseHttpRequestError::InvalidUtf8)?;
        let path = String::from_utf8(path)
            .ok()
            .ok_or(ParseHttpRequestError::InvalidUtf8)?;
        let protocol = String::from_utf8(protocol)
            .ok()
            .ok_or(ParseHttpRequestError::InvalidUtf8)?;
        Ok(HttpRequest {
            path,
            method: HttpMethod::try_from(method.as_str())
                .ok()
                .ok_or(ParseHttpRequestError::InvalidMethod)?,
            protocol,
            headers: header_map,
            body,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseHttpRequestError {
    CantSetTimeout,
    InvalidUtf8,
    InvalidMethod,
    MissingOrIncompleteMethod,
    MissingOrIncompletePath,
    MissingOrIncompleteProtocol,
    OversizedMethod,
    OversizedPath,
    OversizedProtocol,
    OversizedHeaders,
    OversizedBody,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    #[default]
    Get,
    Put,
    Post,
    Head,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
}
impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Get => "GET",
                Self::Put => "PUT",
                Self::Post => "POST",
                Self::Head => "HEAD",
                Self::Delete => "DELETE",
                Self::Connect => "CONNECT",
                Self::Options => "OPTIONS",
                Self::Trace => "TRACE",
                Self::Patch => "PATCH",
            }
        )
    }
}
impl TryFrom<&str> for HttpMethod {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "get" => Ok(HttpMethod::Get),
            "put" => Ok(HttpMethod::Put),
            "post" => Ok(HttpMethod::Post),
            "head" => Ok(HttpMethod::Head),
            "delete" => Ok(HttpMethod::Delete),
            "connect" => Ok(HttpMethod::Connect),
            "options" => Ok(HttpMethod::Options),
            "trace" => Ok(HttpMethod::Trace),
            "patch" => Ok(HttpMethod::Patch),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, net::TcpListener};

    use super::*;

    #[test]
    fn http_client_from_tcpstream() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53627").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53627").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        let _tcp_listener = TcpListener::bind("127.0.0.1:53628").unwrap();
        let good_client = HttpClient {
            incoming: HttpRequest {
                path: "/test/bla".to_owned(),
                method: HttpMethod::Get,
                protocol: "HTTP/1.1".to_owned(),
                headers: {
                    let mut map = HashMap::new();
                    map.insert("accept".to_owned(), "*/*".to_owned());
                    map
                },
                body: b"This is the body!".to_vec(),
            },
            outgoing: None,
            stream: TcpStream::connect("127.0.0.1:53628").unwrap(),
        };
        assert_eq!(client, good_client);
    }
    #[test]
    fn http_response_from_builder() {
        let builder = HttpResponseBuilder::new()
            .code(HttpCode::Ok)
            .message("Ok")
            .protocol("HTTP/1.1")
            .header("accept", "*/*")
            .body(b"This is the body!".to_vec())
            .build()
            .unwrap();
        assert_eq!(
            format!("{}", builder),
            "HTTP/1.1 200 Ok\r\naccept: */*\r\n\r\nThis is the body!"
        );
    }
    #[test]
    fn zero_len_method() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53629").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53629").unwrap();
        client
            .write_all(b" /test/bla HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::InvalidMethod));
        // This means te length of the method wasnt an issue, rather the content of the method was
        // the problem, so this actually passes despite being an Err() type
    }
    #[test]
    fn zero_len_path() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53630").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53630").unwrap();
        client
            .write_all(b"GET  HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        assert_eq!(client.incoming.path, "");
    }
    #[test]
    fn zero_len_protocol() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53631").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53631").unwrap();
        client
            .write_all(b"GET /test/bla \r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        assert_eq!(client.incoming.protocol, "");
    }
    #[test]
    fn zero_len_headers() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53643").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53643").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        assert_eq!(client.incoming.headers, HashMap::new());
    }
    #[test]
    fn zero_len_body() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53644").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53644").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\nAccept: */*\r\n")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        assert_eq!(client.incoming.body, []);
    }

    #[test]
    fn of_size_method() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53632").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53632").unwrap();
        client
            .write_all(b"ABCDEFGHIJ /test/bla HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::InvalidMethod));
        // This means te length of the method wasnt an issue, rather the content of the method was
        // the problem, so this actually passes despite being an Err() type
    }
    #[test]
    fn of_size_path() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53633").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53633").unwrap();
        client
            .write_all(b"GET /1234 HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig {
            max_path_len: 5,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        assert_eq!(client.incoming.path, "/1234");
    }
    #[test]
    fn of_size_protocol() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53634").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53634").unwrap();
        client
            .write_all(b"GET /test/bla ABCDE\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig {
            max_protocol_len: 5,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config).unwrap();
        assert_eq!(client.incoming.protocol, "ABCDE");
    }
    #[test]
    fn of_size_headers() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53640").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53640").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\nABC: DEFGH\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig {
            max_header_len: 10,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(
            client.unwrap().incoming.headers.get("abc").unwrap(),
            "DEFGH"
        );
    }
    #[test]
    fn of_size_body() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53642").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53642").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\nAccept: */*\r\n\r\nABCDEFGHIJ")
            .unwrap();
        let config = HttpRequestConfig {
            max_body_len: 10,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client.unwrap().incoming.body, b"ABCDEFGHIJ".to_vec());
    }
    #[test]
    fn oversized_method() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53641").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53641").unwrap();
        client
            .write_all(b"ABCDEFGHIJK /test/bla HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::OversizedMethod));
    }
    #[test]
    fn oversized_path() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53636").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53636").unwrap();
        client
            .write_all(b"GET /12345 HTTP/1.1\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig {
            max_path_len: 5,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::OversizedPath));
    }
    #[test]
    fn oversized_protocol() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53637").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53637").unwrap();
        client
            .write_all(b"GET /test/bla ABCDEFGHIJK\r\nAccept: */*\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig::default();
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::OversizedProtocol));
    }
    #[test]
    fn oversized_headers() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53638").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53638").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\nABC: DEFGHI\r\n\r\nThis is the body!")
            .unwrap();
        let config = HttpRequestConfig {
            max_header_len: 10,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::OversizedHeaders));
    }
    #[test]
    fn oversized_body() {
        let tcp_listener = TcpListener::bind("127.0.0.1:53639").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:53639").unwrap();
        client
            .write_all(b"GET /test/bla HTTP/1.1\r\nAccept: */*\r\n\r\nABCDEFGHIJK")
            .unwrap();
        let config = HttpRequestConfig {
            max_body_len: 10,
            ..Default::default()
        };
        let client = HttpClient::new(tcp_listener.accept().unwrap().0, &config);
        assert_eq!(client, Err(ParseHttpRequestError::OversizedBody));
    }
}
