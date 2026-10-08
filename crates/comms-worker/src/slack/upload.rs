use super::*;
use js_sys::Uint8Array;

impl WorkerSlackBackend {
    pub(super) async fn upload_blob(&self, arguments: Value) -> Result<Value, String> {
        let blob_id = string_field(&arguments, "blob_id")?;
        let key = format!(
            "{}:{}",
            self.agent.id,
            string_field(&arguments, "idempotency_key")?
        );
        let mut get_params = stage_params(&arguments, "get_params")?;
        let mut complete_params = stage_params(&arguments, "complete_params")?;
        if complete_params.get("files").is_some() {
            return Err("upload completion files are assigned by the host".into());
        }
        let mut record = self
            .load_or_enqueue_delivery(&key, "files.uploadExternal", &arguments)
            .await?;
        if record.state == DeliveryState::Sent {
            let mut result = record.result.unwrap_or(Value::Null);
            result["replayed"] = json!(true);
            return Ok(result);
        }
        if record.state != DeliveryState::Pending {
            return Ok(
                json!({"ok":false,"state":delivery_state_name(record.state),"error":"delivery_requires_reconciliation","file_id":record.result.as_ref().and_then(|v|v.get("file_id"))}),
            );
        }
        let (blob, body) = crate::media::open_blob(&self.env, blob_id)
            .await
            .map_err(|_| "upload media blob was not found".to_string())?;
        let filename = arguments
            .get("filename")
            .and_then(Value::as_str)
            .or(blob.name.as_deref())
            .unwrap_or(blob_id)
            .to_owned();
        get_params["filename"] = json!(filename);
        get_params["length"] = json!(blob.bytes);
        let claim = crate::auth::control_db(&self.env).map_err(|e| e.to_string())?
            .prepare("UPDATE slack_outbox SET state='sending', updated_at=?3 WHERE workspace_id=?1 AND delivery_key=?2 AND agent_id=?4 AND state='pending'")
            .bind(&[JsValue::from_str(&record.workspace_id), JsValue::from_str(&key), JsValue::from_f64(now_ms() as f64), JsValue::from_str(&self.agent.id)])
            .map_err(|e|e.to_string())?.run().await.map_err(|e|e.to_string())?;
        if claim
            .meta()
            .map_err(|e| e.to_string())?
            .and_then(|m| m.changes)
            .unwrap_or(0)
            != 1
        {
            return Ok(json!({"ok":false,"error":"delivery_requires_reconciliation"}));
        }
        record.state = DeliveryState::Sending;
        let result = self
            .upload_stages(
                &mut record,
                get_params,
                &mut complete_params,
                body,
                blob.bytes,
                &blob.mime_type,
            )
            .await;
        match result {
            Ok(result) => {
                record.state = if result["ok"].as_bool() == Some(true) {
                    DeliveryState::Sent
                } else {
                    DeliveryState::Failed
                };
                record.result = Some(result.clone());
                self.save_delivery_record(&record).await?;
                Ok(result)
            }
            Err(error) => {
                record.state = DeliveryState::Ambiguous;
                record.error = Some(error.clone());
                self.save_delivery_record(&record).await?;
                Ok(
                    json!({"ok":false,"state":"ambiguous","error":error,"file_id":record.result.as_ref().and_then(|v|v.get("file_id"))}),
                )
            }
        }
    }

    async fn upload_stages(
        &self,
        record: &mut DeliveryRecord,
        get_params: Value,
        complete_params: &mut Value,
        body: worker::ResponseBody,
        length: usize,
        mime_type: &str,
    ) -> Result<Value, String> {
        let allocated = self
            .runtime
            .invoke(Invocation {
                agent_id: self.agent.id.clone(),
                method: "files.getUploadURLExternal".into(),
                arguments: get_params,
                idempotency_key: None,
            })
            .await
            .map_err(|e| e.to_string())?;
        self.save_method_clock(&allocated).await?;
        if !allocated.ok {
            return Ok(
                json!({"ok":false,"stage":"allocate","body":redacted_error(&allocated.body)}),
            );
        }
        let file_id = string_field(&allocated.body, "file_id")?.to_owned();
        record.result = Some(json!({"file_id":file_id,"stage":"allocated"}));
        self.save_delivery_record(record).await?;
        let url = string_field(&allocated.body, "upload_url")?;
        let fixture_origin = crate::slack_oauth::api_url(&self.env, "")
            .map_err(|_| "upload endpoint unavailable".to_string())?;
        let fixture = self
            .env
            .var("SLACK_FIXTURE_MODE")
            .map(|v| v.to_string() == "1")
            .unwrap_or(false)
            && url
                .strip_prefix(&fixture_origin)
                .is_some_and(|path| path.starts_with("files/upload/"));
        if !valid_upload_url(url) && !fixture {
            return Err("Slack returned an untrusted upload endpoint".into());
        }
        transfer(url, body, length, mime_type).await?;
        record.result = Some(json!({"file_id":file_id,"stage":"transferred"}));
        self.save_delivery_record(record).await?;
        let title = complete_params
            .as_object_mut()
            .and_then(|v| v.remove("title"));
        let mut file = json!({"id":file_id});
        if let Some(title) = title {
            file["title"] = title;
        }
        complete_params["files"] = json!([file]);
        let completed = self
            .runtime
            .invoke(Invocation {
                agent_id: self.agent.id.clone(),
                method: "files.completeUploadExternal".into(),
                arguments: complete_params.clone(),
                idempotency_key: None,
            })
            .await
            .map_err(|e| e.to_string())?;
        self.save_method_clock(&completed).await?;
        Ok(
            json!({"ok":completed.ok,"method":"files.uploadExternal","file_id":file_id,
            "body":redacted_error(&completed.body),"delivery_key":record.key,
            "agent_id":self.agent.id,"workspace_id":self.credentials.team_id,"replayed":false}),
        )
    }
}

fn stage_params(arguments: &Value, field: &str) -> Result<Value, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(json!({})),
        Some(value) if value.is_object() => Ok(value.clone()),
        _ => Err(format!("{field} must be a JSON object")),
    }
}

fn valid_upload_url(url: &str) -> bool {
    url.strip_prefix("https://files.slack.com/upload/")
        .is_some_and(|path| {
            !path.is_empty()
                && !url
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '\\' | '#'))
        })
}

async fn transfer(
    url: &str,
    body: worker::ResponseBody,
    length: usize,
    mime_type: &str,
) -> Result<(), String> {
    let body = match body {
        worker::ResponseBody::Stream(stream) => JsValue::from(stream),
        worker::ResponseBody::Body(bytes) => JsValue::from(Uint8Array::from(bytes.as_slice())),
        worker::ResponseBody::Empty => JsValue::NULL,
    };
    let global = js_sys::global();
    let fetch = Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| "upload fetch unavailable")?
        .dyn_into::<Function>()
        .map_err(|_| "upload fetch unavailable")?;
    let headers = Object::new();
    Reflect::set(
        &headers,
        &JsValue::from_str("content-type"),
        &JsValue::from_str(mime_type),
    )
    .map_err(|_| "upload headers invalid")?;
    Reflect::set(
        &headers,
        &JsValue::from_str("content-length"),
        &JsValue::from_str(&length.to_string()),
    )
    .map_err(|_| "upload length invalid")?;
    let init = Object::new();
    for (key, value) in [("method", "POST"), ("redirect", "manual")] {
        Reflect::set(&init, &JsValue::from_str(key), &JsValue::from_str(value))
            .map_err(|_| "upload request invalid")?;
    }
    Reflect::set(&init, &JsValue::from_str("headers"), &headers)
        .map_err(|_| "upload request invalid")?;
    Reflect::set(&init, &JsValue::from_str("body"), &body).map_err(|_| "upload request invalid")?;
    let promise = fetch
        .call2(&global, &JsValue::from_str(url), &init)
        .map_err(|error| transfer_error(&error, url))?
        .dyn_into::<Promise>()
        .map_err(|error| transfer_error(&error, url))?;
    let response = JsFuture::from(promise)
        .await
        .map_err(|error| transfer_error(&error, url))?
        .dyn_into::<WebResponse>()
        .map_err(|_| "Slack file transfer response invalid")?;
    if response.status() != 200 {
        return Err(format!(
            "Slack file transfer returned HTTP {}",
            response.status()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::valid_upload_url;
    #[test]
    fn upload_endpoints_are_exact_slack_https_origins() {
        assert!(valid_upload_url("https://files.slack.com/upload/v1/opaque"));
        for url in [
            "http://files.slack.com/upload/v1/x",
            "https://files.slack.com.evil/upload/v1/x",
            "https://files.slack.com@evil/upload/v1/x",
            "https://files.slack.com:444/upload/v1/x",
            "https://files.slack.com/upload/v1/x#fragment",
            "https://evil/upload/v1/x",
        ] {
            assert!(!valid_upload_url(url), "{url}");
        }
    }
}

fn transfer_error(error: &JsValue, url: &str) -> String {
    let message = Reflect::get(error, &JsValue::from_str("message"))
        .ok()
        .and_then(|value| value.as_string())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "fetch failed".into());
    format!(
        "Slack file transfer result is uncertain: {}",
        message.replace(url, "[upload endpoint]")
    )
}
