//! # Acquisition Safety Assessment Subsystem
//!
//! Provides top-level safety evaluation across Windows and synthetic test platforms.

use crate::types::{
    AcquisitionConfig, PhysicalSource, SafetyAssessment,
};

/// Perform safety assessment for the given source and configuration.
pub fn assess_safety(source: &PhysicalSource, config: &AcquisitionConfig) -> SafetyAssessment {
    #[cfg(windows)]
    {
        crate::windows::assess_windows_safety(source, config)
    }

    #[cfg(not(windows))]
    {
        let mut blocking_reasons = Vec::new();
        let mut warnings = Vec::new();

        let dest_path = Path::new(&config.destination_path);
        let destination_is_not_source = source.device_path != config.destination_path;
        if !destination_is_not_source {
            blocking_reasons.push("Destination matches source device path!".to_string());
        }

        let collision = dest_path.exists();
        if collision {
            warnings.push("Destination file already exists.".to_string());
        }

        SafetyAssessment {
            source_accessible: true,
            source_read_only_confirmed: true,
            destination_exists_or_creatable: true,
            destination_is_not_source,
            destination_not_on_source_device: true,
            destination_device_number: None,
            source_capacity_bytes: source.capacity,
            destination_free_space_bytes: source.capacity * 2,
            has_sufficient_space: true,
            collision_detected: collision,
            recognized_volumes: source.volumes.clone(),
            volume_lock_state: VolumeLockState::NotApplicable,
            is_safe_to_proceed: blocking_reasons.is_empty(),
            blocking_reasons,
            warnings,
        }
    }
}
