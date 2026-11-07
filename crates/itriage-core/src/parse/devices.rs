//! Device Manager problem codes (CM_PROB_*, cfg.h): the "Code 43" numbers.

use crate::model::Severity;

/// What a problem code means, in Device Manager's terms.
pub fn problem_text(code: u32) -> &'static str {
    match code {
        1 => "isn't configured correctly",
        3 => "driver may be corrupted, or the system is low on memory",
        9 => "reports invalid hardware data",
        10 => "can't start",
        12 => "can't find enough free resources",
        14 => "needs a restart to finish",
        16 => "isn't fully configured (partial resources)",
        18 => "drivers need to be reinstalled",
        19 => "configuration in the registry is incomplete or damaged",
        21 => "is being removed",
        22 => "is disabled",
        24 => "isn't present or isn't working properly",
        28 => "has no driver installed",
        29 => "is disabled in the firmware",
        31 => "isn't working properly: the driver failed to load",
        32 => "driver's service is disabled",
        33 => "can't work out the resources it needs",
        34 => "needs manual configuration",
        35 => "firmware lacks the information to configure it",
        37 => "driver failed to initialise",
        38 => "can't load because a previous driver instance is still loaded",
        39 => "driver is missing or corrupt",
        40 => "driver's registry entry is invalid",
        41 => "driver loaded but the hardware wasn't found",
        42 => "is a duplicate device",
        43 => "stopped after reporting problems (Code 43)",
        44 => "was shut down by an application or service",
        45 => "isn't connected",
        46 => "isn't available while Windows shuts down",
        47 => "is prepared for safe removal",
        48 => "driver is blocked (known compatibility problem)",
        49 => "can't start: the system registry is too large",
        50 => "properties couldn't be applied",
        51 => "is waiting on another device",
        52 => "driver isn't digitally signed",
        53 => "is reserved by the kernel debugger",
        54 => "failed and is being reset",
        _ => "has a problem",
    }
}

/// How much a problem code matters. Disabled, unplugged and "restart to
/// finish" devices are informational; everything else is a real fault.
pub fn problem_severity(code: u32) -> Severity {
    match code {
        14 | 21 | 22 | 45 | 46 | 47 | 53 => Severity::Info,
        _ => Severity::Warning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_problem_codes() {
        assert_eq!(problem_text(43), "stopped after reporting problems (Code 43)");
        assert_eq!(problem_text(28), "has no driver installed");
        assert_eq!(problem_text(999), "has a problem");
        assert_eq!(problem_severity(22), Severity::Info);
        assert_eq!(problem_severity(43), Severity::Warning);
    }
}
