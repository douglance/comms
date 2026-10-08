#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = comms_cli::HttpBackend::from_env()?;
    if std::env::args().any(|arg| arg == "--mcp") {
        let service = std::sync::Arc::new(backend.remote_code_mode()?);
        return comms_codemode::serve_mcp_stdio(service)
            .await
            .map_err(Into::into);
    }
    comms_cli::build_cli(backend).serve().await
}
