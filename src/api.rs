use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OperationOptions {
    pub dry_run: bool,
    pub yes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrisResponse {
    pub ok: bool,
    pub message: String,
    pub data: Value,
}

impl IrisResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn with_data(message: impl Into<String>, data: impl Serialize) -> Result<Self> {
        Ok(Self {
            ok: true,
            message: message.into(),
            data: serde_json::to_value(data)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum IrisRequest {
    Ping,
    DaemonStatus,
    DaemonLog {
        lines: usize,
    },
    SelfStatus,
    SelfStage {
        options: OperationOptions,
    },
    SelfBootstrap {
        options: OperationOptions,
    },
    SelfUpdate {
        options: OperationOptions,
    },
    Install {
        packages: Vec<String>,
        options: OperationOptions,
    },
    Remove {
        packages: Vec<String>,
        options: OperationOptions,
    },
    Purge {
        packages: Vec<String>,
        options: OperationOptions,
    },
    Update {
        packages: Vec<String>,
        options: OperationOptions,
    },
    Search {
        query: String,
    },
    Info {
        package: String,
    },
    Verify {
        packages: Vec<String>,
        full: bool,
    },
    Repair {
        packages: Vec<String>,
        options: OperationOptions,
    },
    Audit,
    GenerationList,
    GenerationSwitch {
        generation: i64,
    },
    GenerationRollback,
    GenerationDiff {
        from: i64,
        to: i64,
    },
    GenerationGc,
    OrphanList,
    OrphanShow {
        package: String,
    },
    OrphanPurge {
        package: Option<String>,
        force: bool,
        options: OperationOptions,
    },
    RepoAdd {
        url: String,
        key: String,
    },
    RepoSync,
    History,
    Pin {
        package: String,
    },
    Why {
        package: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRequestEnvelope {
    pub version: u32,
    pub request: IrisRequest,
}

impl DaemonRequestEnvelope {
    pub fn new(request: IrisRequest) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonResponseEnvelope {
    pub version: u32,
    pub response: IrisResponse,
}

impl DaemonResponseEnvelope {
    pub fn new(response: IrisResponse) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            response,
        }
    }
}
