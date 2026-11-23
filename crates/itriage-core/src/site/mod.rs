//! Checks driven by the site profile (`crate::profile`): required apps with
//! minimum versions, required services, endpoints that must answer, and the
//! site's own read-only checks (`[[check]]`).

pub mod apps;
pub mod checks;
pub mod rules;
pub mod status;
