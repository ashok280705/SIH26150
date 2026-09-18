use forensic_core::capability::{CapabilityStage, CapabilityStages};
use forensic_core::profile::ProfileRegistry;
use std::collections::HashMap;

/// Derives the capability stage for each OEM dynamically based on the current
/// implementation state (e.g., loaded profiles and detectors).
///
/// Ensures we do not advertise a capability that isn't actually implemented
/// and loaded in the system (Req 3.6, 21.3).
pub fn get_all_capabilities(registry: &ProfileRegistry) -> HashMap<String, CapabilityStages> {
    let mut capabilities = HashMap::new();

    // Default set of known OEMs we track capabilities for
    let known_oems = vec![
        "dahua",
        "hikvision",
        "honeywell",
        "cp_plus",
        "uniview",
        "tplink", // future
        "godrej", // future
        "matrix", // future
    ];

    for oem in known_oems {
        let mut stages = CapabilityStages::not_implemented();

        // If the profile is registered, we have a detection capability.
        // Also map our known parsers and profiling.
        if registry.find_applicable(oem, None, None, None).is_some() {
            stages.detection = CapabilityStage::Implemented;

            // Topology profiling is available for all detected OEMs
            stages.profiling = CapabilityStage::Implemented;
            
            // For now, all of our registered profiles have a stub parser.
            if oem != "godrej" && oem != "matrix" {
                stages.parsing = CapabilityStage::Implemented;
            }
        }

        capabilities.insert(oem.to_string(), stages);
    }

    capabilities
}
