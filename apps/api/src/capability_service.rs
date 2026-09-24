use forensic_core::capability::{CapabilityStage, CapabilityStages};
use forensic_core::profile::ProfileRegistry;
use std::collections::HashMap;

/// Derives the capability stage for each OEM from what is actually implemented, so the UI
/// never advertises a capability the platform does not have (Req 3.6, 21.3).
///
/// ## Why this is a table and not a loop over loaded profiles
///
/// A registered profile means the platform can *detect* an OEM. It says nothing about whether
/// a parser reads that OEM's structures, whether a recording can be reconstructed from them,
/// or whether the result can be validated. An earlier revision derived `parsing = Implemented`
/// from profile presence alone, with the comment "all of our registered profiles have a stub
/// parser" — which advertised stub parsers as working implementations.
///
/// Each row below is therefore the honest per-stage state of one OEM path, and a profile is
/// still required before any stage is claimed: a capability that cannot be exercised because
/// its profile is missing is not a capability.
pub fn get_all_capabilities(registry: &ProfileRegistry) -> HashMap<String, CapabilityStages> {
    let mut capabilities = HashMap::new();

    // (oem key, parsing, reconstruction, validation)
    //
    // `Partial` is used where the implementation is real but scoped to the structures and
    // firmware layouts the platform has evidence for — which is the truthful answer for every
    // OEM here, since none has been validated across a vendor's whole product range.
    let oems: &[(&str, CapabilityStage, CapabilityStage, CapabilityStage)] = &[
        // Dahua: DHFS 4.1 partition/block-table/DHII/DHAV structure set, chain reconstruction
        // and elementary-stream export.
        (
            "dahua",
            CapabilityStage::Implemented,
            CapabilityStage::Implemented,
            CapabilityStage::Implemented,
        ),
        // Hikvision: boot identifier, HIKBTREE page traversal, 1 GiB blocks with footer clip
        // index, MPEG-PS/PES clip framing, clip reconstruction and export. Marked `Partial`
        // rather than `Implemented` because the structure set has been exercised against
        // synthetic volumes built from the documented layout and not against a validated
        // corpus of real firmware images; several clip-slot field meanings remain provisional.
        (
            "hikvision",
            CapabilityStage::Partial,
            CapabilityStage::Partial,
            CapabilityStage::Partial,
        ),
        // T-Link: container framing only.
        (
            "tplink",
            CapabilityStage::Partial,
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
        ),
        // The remaining OEMs have a profile and a detector but no structural parser yet.
        // Reporting `NotImplemented` here is the point of this table.
        (
            "honeywell",
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
        ),
        (
            "cp_plus",
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
        ),
        (
            "uniview",
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
        ),
        (
            "godrej",
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
        ),
        (
            "matrix",
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
            CapabilityStage::NotImplemented,
        ),
    ];

    for (oem, parsing, reconstruction, validation) in oems {
        let mut stages = CapabilityStages::not_implemented();
        // Detection and topology profiling both rest on the profile being loaded. Without one,
        // nothing downstream can run either, so every stage stays NotImplemented.
        if registry.find_applicable(oem, None, None, None).is_some() {
            stages.detection = CapabilityStage::Implemented;
            stages.profiling = CapabilityStage::Implemented;
            stages.parsing = *parsing;
            stages.reconstruction = *reconstruction;
            stages.validation = *validation;
        }
        capabilities.insert((*oem).to_string(), stages);
    }

    capabilities
}
