//! # Pipeline Job Execution Coordinator
//!
//! Provides asynchronous, non-blocking pipeline execution tracking, progress reporting,
//! and cancellation coordination at the API/application layer.
//!
//! This coordinator strictly coordinates execution and progress/cancellation lifecycles;
//! it contains NO forensic or analytical logic.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use evidence_reader::CancellationToken;
use forensic_core::EvidenceId;
use pipeline::{PipelineProgress, PipelineRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgressInfo {
    pub stage: String,
    pub stage_name: String,
    pub stage_index: usize,
    pub total_stages: usize,
    pub description: String,
    pub fraction: Option<f64>,
}

impl From<PipelineProgress> for JobProgressInfo {
    fn from(p: PipelineProgress) -> Self {
        Self {
            stage: p.stage.to_string(),
            stage_name: p.stage_name,
            stage_index: p.stage_index,
            total_stages: p.total_stages,
            description: p.description,
            fraction: p.fraction,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    pub evidence_id: Uuid,
    pub state: JobState,
    pub stage: Option<String>,
    pub progress: Option<JobProgressInfo>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<PipelineRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStartResponse {
    pub job_id: Uuid,
    pub state: JobState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCancelResponse {
    pub job_id: Uuid,
    pub state: JobState,
    pub message: String,
}

pub struct JobEntry {
    pub id: Uuid,
    pub evidence_id: EvidenceId,
    pub state: JobState,
    pub stage: Option<String>,
    pub progress: Option<JobProgressInfo>,
    pub error: Option<String>,
    pub result: Option<PipelineRun>,
    pub cancel_token: CancellationToken,
}

#[derive(Clone, Default)]
pub struct JobCoordinator {
    jobs: Arc<RwLock<HashMap<Uuid, Arc<RwLock<JobEntry>>>>>,
}

impl JobCoordinator {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates and registers a new job entry, returning its ID, an Arc to the entry,
    /// and its cancellation token.
    pub async fn create_job(
        &self,
        evidence_id: EvidenceId,
    ) -> (Uuid, Arc<RwLock<JobEntry>>, CancellationToken) {
        let job_id = Uuid::new_v4();
        let cancel_token = CancellationToken::new();
        let entry = Arc::new(RwLock::new(JobEntry {
            id: job_id,
            evidence_id,
            state: JobState::Queued,
            stage: None,
            progress: None,
            error: None,
            result: None,
            cancel_token: cancel_token.clone(),
        }));

        self.jobs.write().await.insert(job_id, entry.clone());
        (job_id, entry, cancel_token)
    }

    /// Queries the current status of a job.
    pub async fn get_job_status(&self, job_id: &Uuid) -> Option<JobStatusResponse> {
        let entry_arc = {
            let guard = self.jobs.read().await;
            guard.get(job_id).cloned()?
        };
        let guard = entry_arc.read().await;
        Some(JobStatusResponse {
            job_id: guard.id,
            evidence_id: guard.evidence_id.0,
            state: guard.state,
            stage: guard.stage.clone(),
            progress: guard.progress.clone(),
            error: guard.error.clone(),
            result: guard.result.clone(),
        })
    }

    /// Requests cancellation of a running or queued job.
    pub async fn cancel_job(&self, job_id: &Uuid) -> Option<JobCancelResponse> {
        let entry_arc = {
            let guard = self.jobs.read().await;
            guard.get(job_id).cloned()?
        };
        let mut guard = entry_arc.write().await;
        match guard.state {
            JobState::Queued | JobState::Running => {
                guard.cancel_token.cancel();
                guard.state = JobState::Cancelled;
                Some(JobCancelResponse {
                    job_id: *job_id,
                    state: JobState::Cancelled,
                    message: "Cancellation requested".to_string(),
                })
            }
            other => Some(JobCancelResponse {
                job_id: *job_id,
                state: other,
                message: format!("Job already in terminal state: {other:?}"),
            }),
        }
    }
}
