use clap::Parser;
use iris::cli::{Cli, FrontendRequest, Transport};
use iris::{Iris, IrisResponse};
use serde::Serialize;
use serde_json::{Value, json};

fn main() {
    let cli = Cli::parse();
    let render = cli.render_options();

    match cli.into_frontend_request().and_then(run) {
        Ok(response) => {
            if render.json {
                match render_json_output(&response) {
                    Ok(output) => println!("{}", output),
                    Err(message) => {
                        println!("{}", minimal_json_error(&message));
                        std::process::exit(1);
                    }
                }
            } else {
                println!("{}", response.message);
            }
        }
        Err(err) => {
            if render.json {
                let response = IrisResponse::error(err.to_string());
                match render_json_output(&response) {
                    Ok(output) => println!("{}", output),
                    Err(message) => println!("{}", minimal_json_error(&message)),
                }
            } else {
                eprintln!("error: {err}");
            }
            std::process::exit(1);
        }
    }
}

fn run(frontend: FrontendRequest) -> iris::Result<IrisResponse> {
    let FrontendRequest {
        root,
        transport,
        socket,
        request,
        ..
    } = frontend;

    match transport {
        Transport::Direct => {
            let app = Iris::open(root)?;
            app.execute(request)
        }
        Transport::Daemon => iris::daemon::request(root, socket, request),
    }
}

fn render_json_output<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map_err(|err| format!("failed to serialize CLI JSON response: {}", err))
}

fn minimal_json_error(message: &str) -> String {
    let value = json!({
        "ok": false,
        "message": message,
        "data": Value::Null,
    });
    match serde_json::to_string_pretty(&value) {
        Ok(output) => output,
        Err(_) => format!(
            "{{\"ok\":false,\"message\":{},\"data\":null}}",
            serde_json::Value::String(message.to_string())
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{minimal_json_error, render_json_output};
    use serde::Serialize;
    use serde::ser::Serializer;

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    #[test]
    fn json_render_helper_returns_error_instead_of_panicking() {
        let err = render_json_output(&FailingSerialize)
            .expect_err("failing serializer should not panic the CLI");
        assert!(err.contains("failed to serialize CLI JSON response"));
    }

    #[test]
    fn minimal_json_error_is_structured_json() {
        let rendered = minimal_json_error("boom");
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("fallback must remain valid json");

        assert_eq!(value["ok"].as_bool(), Some(false));
        assert_eq!(value["message"].as_str(), Some("boom"));
        assert!(value["data"].is_null());
    }
}
