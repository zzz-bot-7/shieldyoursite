mod headers;
mod platform;
mod resources;

pub(crate) use headers::evaluate_headers;
pub(crate) use platform::detect_platform;
pub(crate) use resources::detect_resources;
