//! The duties that need to be performed in the Deposit State Machine in response to the state
//! transitions.

/// The duties that need to be performed to drive the Deposit State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositDuty {
    /// TODO: (@MdTeach)
    PublishDepositNonce,
    /// TODO: (@MdTeach)
    PublishDepositPartial,
    /// TODO: (@MdTeach)
    PublishDeposit,
    /// TODO: (@mukeshdroid)
    FulfillWithdrawal,
    /// TODO: (@mukeshdroid)
    RequestPayoutNonces,
    /// TODO: (@mukeshdroid)
    PublishPayoutNonce,
    /// TODO: (@mukeshdroid)
    RequestPayoutPartials,
    /// TODO: (@mukeshdroid)
    PublishPayoutPartial,
    /// TODO: (@Rajil1213)
    PublishPayout,
}

impl std::fmt::Display for DepositDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let duty_str = match self {
            DepositDuty::PublishDepositNonce => "PublishDepositNonce",
            DepositDuty::PublishDepositPartial => "PublishDepositPartial",
            DepositDuty::PublishDeposit => "PublishDeposit",
            DepositDuty::FulfillWithdrawal => "FulfillWithdrawal",
            DepositDuty::RequestPayoutNonces => "RequestPayoutNonces",
            DepositDuty::PublishPayoutNonce => "PublishPayoutNonce",
            DepositDuty::RequestPayoutPartials => "RequestPayoutPartials",
            DepositDuty::PublishPayoutPartial => "PublishPayoutPartial",
            DepositDuty::PublishPayout => "PublishPayout",
        };
        write!(f, "{}", duty_str)
    }
}
