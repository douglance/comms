use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use comms_cli::{HttpBackend, build_cli};
use comms_core::Backend;
use incurs::cli::Runtime;
use serde_json::{Value, json};

#[derive(Clone)]
struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    pause_after_bytes: Option<PauseAfterBytes>,
}

#[derive(Clone)]
struct PauseAfterBytes {
    bytes: usize,
    release: Arc<(Mutex<bool>, Condvar)>,
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().expect("mock server thread should exit");
        }
    }
}

fn response(status: u16, body: impl Into<Vec<u8>>) -> MockResponse {
    MockResponse {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: body.into(),
        pause_after_bytes: None,
    }
}

fn spawn_server(responses: Vec<MockResponse>) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let handle = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set timeout");
            let request = read_request(&mut stream);
            recorded.lock().unwrap().push(request);
            let reason = if response.status >= 400 {
                "Error"
            } else {
                "OK"
            };
            let mut bytes = format!(
                "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
                response.status,
                reason,
                response.body.len()
            )
            .into_bytes();
            for (name, value) in response.headers {
                bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            bytes.extend_from_slice(b"\r\n");
            stream.write_all(&bytes).expect("write response");
            if let Some(pause) = response.pause_after_bytes {
                let split = pause.bytes.min(response.body.len());
                stream
                    .write_all(&response.body[..split])
                    .expect("write first response chunk");
                stream.flush().expect("flush first response chunk");
                let (lock, condvar) = &*pause.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = condvar.wait(released).unwrap();
                }
                stream
                    .write_all(&response.body[split..])
                    .expect("write remaining response chunk");
            } else {
                stream
                    .write_all(&response.body)
                    .expect("write response body");
            }
        }
    });
    MockServer {
        url,
        requests,
        handle: Some(handle),
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> RecordedRequest {
    let mut buffer = Vec::new();
    let mut scratch = [0_u8; 1024];
    loop {
        let read = stream.read(&mut scratch).expect("read request");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&scratch[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .expect("headers complete");
    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap().to_string();
    let path = request_parts.next().unwrap().to_string();
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut scratch).expect("read body");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&scratch[..read]);
    }
    RecordedRequest {
        method,
        path,
        headers,
        body: buffer[header_end..header_end + content_length].to_vec(),
    }
}

#[tokio::test]
async fn backend_posts_json_and_unwraps_success_envelope() {
    let server = spawn_server(vec![response(
        200,
        br#"{"ok":true,"data":{"rows":[{"x":1}]}}"#.as_slice(),
    )]);
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let output = backend
        .call("sql", json!({"sql":"select 1","params":[]}))
        .await
        .unwrap();

    assert_eq!(output, json!({"rows":[{"x":1}]}));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/api/sql");
    assert_eq!(requests[0].headers["authorization"], "Bearer agent-token");
}

#[tokio::test]
async fn backend_does_not_retry_failed_mutating_requests() {
    let server = spawn_server(vec![response(
        500,
        br#"{"ok":false,"error":{"message":"boom"}}"#.as_slice(),
    )]);
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let error = backend
        .call("sql", json!({"sql":"insert into t values (1)"}))
        .await
        .unwrap_err();

    assert!(error.contains("boom"), "{error}");
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn backend_strips_only_top_level_null_fields_from_command_json() {
    let server = spawn_server(vec![response(
        200,
        br#"{"ok":true,"data":{"rows":[]}}"#.as_slice(),
    )]);
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    backend
        .call(
            "sql",
            json!({"sql":"select ?","params":[null,"kept"],"bookmark":null}),
        )
        .await
        .unwrap();

    let requests = server.requests.lock().unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body, json!({"sql":"select ?","params":[null,"kept"]}));
}

#[tokio::test]
async fn backend_refuses_redirects_instead_of_replaying_credentials() {
    let server = spawn_server(vec![MockResponse {
        status: 307,
        headers: vec![(
            "location".to_string(),
            "http://127.0.0.1:9/steal".to_string(),
        )],
        body: Vec::new(),
        pause_after_bytes: None,
    }]);
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let error = backend.call("schema", json!({})).await.unwrap_err();

    assert_eq!(error, "redirects are not followed");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers["authorization"], "Bearer agent-token");
}

#[test]
fn backend_rejects_remote_cleartext_urls() {
    let error = HttpBackend::new("http://example.com", None).unwrap_err();
    assert!(error.contains("HTTPS"), "{error}");
}

#[tokio::test]
async fn blob_put_file_uploads_raw_media() {
    let server = spawn_server(vec![response(
        200,
        br#"{"ok":true,"data":{"id":"blob_1","mime_type":"text/plain","bytes":2}}"#.as_slice(),
    )]);
    let input_path = std::env::temp_dir().join(format!(
        "comms-cli-upload-{}-{}.txt",
        std::process::id(),
        unique_suffix()
    ));
    tokio::fs::write(&input_path, b"hi").await.unwrap();
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let output = backend
        .call(
            "blob_put",
            json!({"file": input_path, "mime_type":"text/plain", "name":"note.txt"}),
        )
        .await
        .unwrap();

    assert_eq!(output["id"], "blob_1");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests[0].path, "/media");
    assert_eq!(requests[0].headers["content-type"], "text/plain");
    assert_eq!(requests[0].headers["x-comms-name"], "note.txt");
    assert_eq!(requests[0].body, b"hi");
}

#[tokio::test]
async fn blob_put_large_file_uploads_ordered_multipart_parts() {
    let server = spawn_server(vec![
        response(
            201,
            br#"{"ok":true,"data":{"id":"blob/slash","upload_id":"upload id","mime_type":"application/octet-stream","name":"large.bin"}}"#.as_slice(),
        ),
        response(
            200,
            br#"{"ok":true,"data":{"part_number":1,"etag":"etag-1"}}"#.as_slice(),
        ),
        response(
            200,
            br#"{"ok":true,"data":{"part_number":2,"etag":"etag-2"}}"#.as_slice(),
        ),
        response(
            200,
            br#"{"ok":true,"data":{"id":"blob/slash","mime_type":"application/octet-stream","bytes":8388611,"etag":"done"}}"#.as_slice(),
        ),
    ]);
    let part_bytes = 8 * 1024 * 1024;
    let data: Vec<u8> = (0..part_bytes + 3)
        .map(|index| (index % 251) as u8)
        .collect();
    let input_path = std::env::temp_dir().join(format!(
        "comms-cli-large-upload-{}-{}.bin",
        std::process::id(),
        unique_suffix()
    ));
    tokio::fs::write(&input_path, &data).await.unwrap();
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let output = backend
        .call(
            "blob_put",
            json!({"file": input_path, "mime_type":"application/octet-stream", "name":"large.bin"}),
        )
        .await
        .unwrap();

    assert_eq!(output["id"], "blob/slash");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/uploads");
    assert_eq!(requests[1].method, "PUT");
    assert_eq!(requests[1].path, "/uploads/blob%2Fslash/upload%20id/1");
    assert_eq!(requests[1].body, data[..part_bytes]);
    assert_eq!(requests[2].method, "PUT");
    assert_eq!(requests[2].path, "/uploads/blob%2Fslash/upload%20id/2");
    assert_eq!(requests[2].body, data[part_bytes..]);
    assert_eq!(requests[3].method, "POST");
    assert_eq!(
        requests[3].path,
        "/uploads/blob%2Fslash/upload%20id/complete"
    );
    let complete: Value = serde_json::from_slice(&requests[3].body).unwrap();
    assert_eq!(
        complete,
        json!({"parts":[{"part_number":1,"etag":"etag-1"},{"part_number":2,"etag":"etag-2"}]})
    );
}

#[tokio::test]
async fn blob_put_large_file_aborts_after_known_part_failure_without_retry() {
    let server = spawn_server(vec![
        response(
            201,
            br#"{"ok":true,"data":{"id":"blob_1","upload_id":"upload_1","mime_type":"application/octet-stream"}}"#.as_slice(),
        ),
        response(
            200,
            br#"{"ok":true,"data":{"part_number":1,"etag":"etag-1"}}"#.as_slice(),
        ),
        response(
            500,
            br#"{"ok":false,"error":{"code":"PART_FAILED","message":"part broke"}}"#.as_slice(),
        ),
        response(
            200,
            br#"{"ok":true,"data":{"id":"blob_1","upload_id":"upload_1","aborted":true}}"#.as_slice(),
        ),
    ]);
    let part_bytes = 8 * 1024 * 1024;
    let data = vec![7_u8; part_bytes + 1];
    let input_path = std::env::temp_dir().join(format!(
        "comms-cli-large-upload-fail-{}-{}.bin",
        std::process::id(),
        unique_suffix()
    ));
    tokio::fs::write(&input_path, &data).await.unwrap();
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let error = backend
        .call("blob_put", json!({"file": input_path}))
        .await
        .unwrap_err();

    assert!(error.contains("PART_FAILED"), "{error}");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].path, "/uploads/blob_1/upload_1/1");
    assert_eq!(requests[2].path, "/uploads/blob_1/upload_1/2");
    assert_eq!(requests[3].method, "DELETE");
    assert_eq!(requests[3].path, "/uploads/blob_1/upload_1");
}

#[tokio::test]
async fn blob_get_output_downloads_raw_media_to_requested_file() {
    let mut media = response(200, b"hello".as_slice());
    media.headers = vec![("content-type".to_string(), "text/plain".to_string())];
    let server = spawn_server(vec![media]);
    let output_path = std::env::temp_dir().join(format!(
        "comms-cli-download-{}-{}.txt",
        std::process::id(),
        unique_suffix()
    ));
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();

    let output = backend
        .call("blob_get", json!({"id":"blob_1", "output": output_path}))
        .await
        .unwrap();

    assert_eq!(output["id"], "blob_1");
    assert_eq!(output["bytes"], 5);
    assert_eq!(tokio::fs::read(&output_path).await.unwrap(), b"hello");
    assert_eq!(server.requests.lock().unwrap()[0].path, "/media/blob_1");
}

#[tokio::test]
async fn blob_get_output_streams_chunks_before_response_finishes() {
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let mut media = response(200, b"helloworld".as_slice());
    media.headers = vec![("content-type".to_string(), "text/plain".to_string())];
    media.pause_after_bytes = Some(PauseAfterBytes {
        bytes: 5,
        release: Arc::clone(&release),
    });
    let server = spawn_server(vec![media]);
    let output_path = std::env::temp_dir().join(format!(
        "comms-cli-stream-download-{}-{}.txt",
        std::process::id(),
        unique_suffix()
    ));
    let backend = HttpBackend::new(&server.url, Some("agent-token".to_string())).unwrap();
    let task_output_path = output_path.clone();
    let handle = tokio::spawn(async move {
        backend
            .call(
                "blob_get",
                json!({"id":"blob/stream", "output": task_output_path}),
            )
            .await
    });

    let observed_partial = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(bytes) = tokio::fs::read(&output_path).await
                && bytes == b"hello"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    {
        let (lock, condvar) = &*release;
        *lock.lock().unwrap() = true;
        condvar.notify_all();
    }
    assert!(
        observed_partial.is_ok(),
        "download did not stream partial output before response completed"
    );
    let output = handle.await.unwrap().unwrap();

    assert_eq!(output["bytes"], 10);
    assert_eq!(tokio::fs::read(&output_path).await.unwrap(), b"helloworld");
    assert_eq!(
        server.requests.lock().unwrap()[0].path,
        "/media/blob%2Fstream"
    );
}

#[tokio::test]
async fn agent_join_uses_invitation_without_authorization_header() {
    let server = spawn_server(vec![response(
        200,
        br#"{"ok":true,"data":{"agent_id":"agent_1","token":"tok","expires_at":1790812800}}"#
            .as_slice(),
    )]);
    let cli = build_cli(HttpBackend::new(&server.url, None).unwrap());
    let mut env = HashMap::new();
    env.insert("COMMS_URL".to_string(), server.url.clone());
    let mut output = Vec::new();

    let status = cli
        .run_to(
            vec![
                "agent".into(),
                "join".into(),
                "--invitation".into(),
                "invite_1".into(),
                "--json".into(),
            ],
            &mut output,
            Runtime::new("comms", env, false),
        )
        .await
        .unwrap();

    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["agent_id"], "agent_1");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests[0].path, "/agent/join");
    assert!(!requests[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn agent_invite_uses_owner_token_from_environment() {
    let server = spawn_server(vec![response(
        200,
        br#"{"ok":true,"data":{"invitation":"invite_1","expires_at":1790812800}}"#.as_slice(),
    )]);
    let cli = build_cli(HttpBackend::new(&server.url, None).unwrap());
    let mut env = HashMap::new();
    env.insert("COMMS_URL".to_string(), server.url.clone());
    env.insert("COMMS_OWNER_TOKEN".to_string(), "owner-token".to_string());
    let mut output = Vec::new();

    let status = cli
        .run_to(
            vec![
                "agent".into(),
                "invite".into(),
                "--label".into(),
                "researcher".into(),
                "--ttl-seconds".into(),
                "60".into(),
                "--json".into(),
            ],
            &mut output,
            Runtime::new("comms", env, false),
        )
        .await
        .unwrap();

    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["invitation"], "invite_1");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests[0].path, "/owner/invite");
    assert_eq!(requests[0].headers["authorization"], "Bearer owner-token");
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body, json!({"label":"researcher","ttl_seconds":60}));
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[tokio::test]
async fn question_wait_polls_until_the_answer_is_terminal() {
    let server = spawn_server(vec![
        response(200, br#"{"ok":true,"data":{"question":{"id":"q_one","state":"waiting"}}}"#.to_vec()),
        response(200, br#"{"ok":true,"data":{"question":{"id":"q_one","state":"answered","answer":{"value":"yes"}}}}"#.to_vec()),
    ]);
    let backend = HttpBackend::new(&server.url, Some("agent-token".into())).unwrap();
    let result = backend
        .call("question_wait", json!({"id":"q_one"}))
        .await
        .unwrap();
    assert_eq!(
        result.pointer("/question/answer/value"),
        Some(&json!("yes"))
    );
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.path == "/api/question/status"));
}
