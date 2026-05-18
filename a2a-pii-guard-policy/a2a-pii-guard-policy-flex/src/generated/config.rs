use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "errorCodeOnReject", default = "default_error_code_on_reject")]
    pub error_code_on_reject: i32,
    #[serde(alias = "predefinedEntities")]
    pub predefined_entities: Option<Vec<PredefinedEntity>>,
    #[serde(alias = "customEntities")]
    pub custom_entities: Option<Vec<CustomEntity>>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct PredefinedEntity {
    #[serde(alias = "type")]
    pub pii_type: String,
    #[serde(alias = "actions")]
    pub actions: Vec<String>,
    #[serde(alias = "reportPolicyViolationOnLog", default = "default_report_policy_violation_on_log")]
    pub report_policy_violation_on_log: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CustomEntity {
    pub regex: String,
    pub name: String,
    #[serde(alias = "actions")]
    pub actions: Vec<String>,
    #[serde(alias = "reportPolicyViolationOnLog", default = "default_report_policy_violation_on_log")]
    pub report_policy_violation_on_log: bool,
}

fn default_report_policy_violation_on_log() -> bool {
    true
}

fn default_error_code_on_reject() -> i32 {
    -32023
}
