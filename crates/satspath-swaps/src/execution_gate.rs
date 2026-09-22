use crate::errors::{Result, SwapError};
use crate::types::SwapKind;

pub fn claim_refund_builders_available(kind: SwapKind) -> bool {
    match kind {
        SwapKind::Submarine | SwapKind::Reverse | SwapKind::Chain => true,
    }
}

pub fn ensure_claim_refund_builders_available(kind: SwapKind) -> Result<()> {
    if claim_refund_builders_available(kind) {
        Ok(())
    } else {
        Err(SwapError::Key(format!(
            "{kind:?} execution blocked: claim/refund transaction builder is not implemented"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_allowed_when_claim_refund_builder_available() {
        assert!(ensure_claim_refund_builders_available(SwapKind::Submarine).is_ok());
        assert!(ensure_claim_refund_builders_available(SwapKind::Reverse).is_ok());
        assert!(ensure_claim_refund_builders_available(SwapKind::Chain).is_ok());
    }
}
