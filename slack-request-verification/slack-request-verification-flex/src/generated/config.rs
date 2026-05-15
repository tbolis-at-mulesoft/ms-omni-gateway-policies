use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "rejectOnFailure")]
    pub reject_on_failure: Option<bool>,
    #[serde(alias = "signingSecret")]
    pub signing_secret: String,
    #[serde(alias = "timestampToleranceSeconds")]
    pub timestamp_tolerance_seconds: Option<i64>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
