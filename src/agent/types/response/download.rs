use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Download {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_chunks: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_screenshot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_num: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_data: Option<String>,
}

impl Download {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_file(
        total_chunks: u32,
        chunk_size: u32,
        filename: impl Into<String>,
        full_path: impl Into<String>,
    ) -> Self {
        Self {
            total_chunks: Some(total_chunks),
            chunk_size: Some(chunk_size),
            filename: Some(filename.into()),
            full_path: Some(full_path.into()),
            ..Default::default()
        }
    }

    pub fn for_chunk(
        file_id: impl Into<String>,
        chunk_num: u32,
        chunk_data: impl Into<String>,
    ) -> Self {
        Self {
            file_id: Some(file_id.into()),
            chunk_num: Some(chunk_num),
            chunk_data: Some(chunk_data.into()),
            ..Default::default()
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}
