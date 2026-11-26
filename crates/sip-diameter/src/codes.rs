//! Diameter command, application, AVP and result codes used by the IMS
//! modules (RFC 6733, RFC 4006, 3GPP TS 29.228/29.229 Cx, 29.214 Rx,
//! 32.299 Ro).
//!
//! Each kind of code has its own type ([`AvpCode`], [`CmdCode`], [`AppId`],
//! [`VendorId`], [`ResultCode`]): a code passed where another kind is
//! expected doesn't compile. Enumerated AVP values (Server-Assignment-Type,
//! CC-Request-Type) stay plain `u32`s.

use std::fmt;

macro_rules! code {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        #[repr(transparent)]
        pub struct $name(pub u32);

        impl $name {
            /// The raw value.
            pub const fn get(self) -> u32 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl From<$name> for u32 {
            fn from(c: $name) -> u32 {
                c.0
            }
        }
    };
}

code!(
    /// An AVP code.
    AvpCode
);
code!(
    /// A command code (24 bits on the wire).
    CmdCode
);
code!(
    /// An application id (Auth-/Acct-Application-Id, the header's
    /// Application-ID).
    AppId
);
code!(
    /// A vendor id (Vendor-Id, an AVP's vendor field).
    VendorId
);
code!(
    /// A Result-Code or Experimental-Result-Code value.
    ResultCode
);

pub const VENDOR_3GPP: VendorId = VendorId(10415);
pub const V: Option<VendorId> = Some(VENDOR_3GPP);

// Applications
pub const APP_COMMON: AppId = AppId(0);
/// The Relay application: matches every application in a CER/CEA.
pub const APP_RELAY: AppId = AppId(0xffff_ffff);
pub const APP_CC: AppId = AppId(4); // Credit-Control (Ro)
pub const APP_CX: AppId = AppId(16777216);
pub const APP_RX: AppId = AppId(16777236);

// Commands
pub const CMD_CE: CmdCode = CmdCode(257);
pub const CMD_DW: CmdCode = CmdCode(280);
pub const CMD_DP: CmdCode = CmdCode(282);
pub const CMD_UAR: CmdCode = CmdCode(300);
pub const CMD_SAR: CmdCode = CmdCode(301);
pub const CMD_LIR: CmdCode = CmdCode(302);
pub const CMD_MAR: CmdCode = CmdCode(303);
pub const CMD_RTR: CmdCode = CmdCode(304);
pub const CMD_PPR: CmdCode = CmdCode(305);
pub const CMD_AA: CmdCode = CmdCode(265);
pub const CMD_RA: CmdCode = CmdCode(258);
pub const CMD_ST: CmdCode = CmdCode(275);
pub const CMD_AS: CmdCode = CmdCode(274);
pub const CMD_CC: CmdCode = CmdCode(272);

// Base AVPs
pub const USER_NAME: AvpCode = AvpCode(1);
pub const FRAMED_IP_ADDRESS: AvpCode = AvpCode(8);
pub const EVENT_TIMESTAMP: AvpCode = AvpCode(55);
pub const DIGEST_REALM: AvpCode = AvpCode(104);
pub const DIGEST_QOP: AvpCode = AvpCode(110);
pub const DIGEST_ALGORITHM: AvpCode = AvpCode(111);
pub const DIGEST_HA1: AvpCode = AvpCode(121);
pub const HOST_IP_ADDRESS: AvpCode = AvpCode(257);
pub const AUTH_APPLICATION_ID: AvpCode = AvpCode(258);
pub const ACCT_APPLICATION_ID: AvpCode = AvpCode(259);
pub const VENDOR_SPECIFIC_APPLICATION_ID: AvpCode = AvpCode(260);
pub const SESSION_ID: AvpCode = AvpCode(263);
pub const ORIGIN_HOST: AvpCode = AvpCode(264);
pub const SUPPORTED_VENDOR_ID: AvpCode = AvpCode(265);
pub const VENDOR_ID: AvpCode = AvpCode(266);
pub const FIRMWARE_REVISION: AvpCode = AvpCode(267);
pub const RESULT_CODE: AvpCode = AvpCode(268);
pub const PRODUCT_NAME: AvpCode = AvpCode(269);
pub const DISCONNECT_CAUSE: AvpCode = AvpCode(273);
pub const AUTH_SESSION_STATE: AvpCode = AvpCode(277);
pub const ORIGIN_STATE_ID: AvpCode = AvpCode(278);
pub const DESTINATION_REALM: AvpCode = AvpCode(283);
pub const DESTINATION_HOST: AvpCode = AvpCode(293);
pub const TERMINATION_CAUSE: AvpCode = AvpCode(295);
pub const ORIGIN_REALM: AvpCode = AvpCode(296);
pub const EXPERIMENTAL_RESULT: AvpCode = AvpCode(297);
pub const EXPERIMENTAL_RESULT_CODE: AvpCode = AvpCode(298);

// Credit control (RFC 4006)
pub const CC_REQUEST_NUMBER: AvpCode = AvpCode(415);
pub const CC_REQUEST_TYPE: AvpCode = AvpCode(416);
pub const CC_TIME: AvpCode = AvpCode(420);
pub const FINAL_UNIT_INDICATION: AvpCode = AvpCode(430);
pub const GRANTED_SERVICE_UNIT: AvpCode = AvpCode(431);
pub const REQUESTED_SERVICE_UNIT: AvpCode = AvpCode(437);
pub const SUBSCRIPTION_ID: AvpCode = AvpCode(443);
pub const SUBSCRIPTION_ID_DATA: AvpCode = AvpCode(444);
pub const USED_SERVICE_UNIT: AvpCode = AvpCode(446);
pub const SUBSCRIPTION_ID_TYPE: AvpCode = AvpCode(450);
pub const MULTIPLE_SERVICES_CREDIT_CONTROL: AvpCode = AvpCode(456);
pub const SERVICE_CONTEXT_ID: AvpCode = AvpCode(461);
pub const CC_INITIAL: u32 = 1;
pub const CC_UPDATE: u32 = 2;
pub const CC_TERMINATION: u32 = 3;

// Cx (3GPP, vendor 10415)
pub const VISITED_NETWORK_IDENTIFIER: AvpCode = AvpCode(600);
pub const PUBLIC_IDENTITY: AvpCode = AvpCode(601);
pub const SERVER_NAME: AvpCode = AvpCode(602);
pub const SERVER_CAPABILITIES: AvpCode = AvpCode(603);
pub const MANDATORY_CAPABILITY: AvpCode = AvpCode(604);
pub const OPTIONAL_CAPABILITY: AvpCode = AvpCode(605);
pub const USER_AUTHORIZATION_TYPE: AvpCode = AvpCode(623);
pub const USER_DATA: AvpCode = AvpCode(606);
pub const SIP_NUMBER_AUTH_ITEMS: AvpCode = AvpCode(607);
pub const SIP_AUTHENTICATION_SCHEME: AvpCode = AvpCode(608);
pub const SIP_AUTHENTICATE: AvpCode = AvpCode(609);
pub const SIP_AUTHORIZATION: AvpCode = AvpCode(610);
pub const SIP_AUTH_DATA_ITEM: AvpCode = AvpCode(612);
pub const SIP_ITEM_NUMBER: AvpCode = AvpCode(613);
pub const SERVER_ASSIGNMENT_TYPE: AvpCode = AvpCode(614);
pub const DEREGISTRATION_REASON: AvpCode = AvpCode(615);
pub const USER_DATA_ALREADY_AVAILABLE: AvpCode = AvpCode(624);
pub const CONFIDENTIALITY_KEY: AvpCode = AvpCode(625);
pub const INTEGRITY_KEY: AvpCode = AvpCode(626);
pub const SIP_DIGEST_AUTHENTICATE: AvpCode = AvpCode(635);

// Server-Assignment-Type
pub const SAT_REGISTRATION: u32 = 1;
pub const SAT_RE_REGISTRATION: u32 = 2;
pub const SAT_UNREGISTERED_USER: u32 = 3;
pub const SAT_USER_DEREGISTRATION: u32 = 5;

// Rx (3GPP, vendor 10415)
pub const AF_APPLICATION_IDENTIFIER: AvpCode = AvpCode(504);
pub const FLOW_DESCRIPTION: AvpCode = AvpCode(507);
pub const MEDIA_COMPONENT_DESCRIPTION: AvpCode = AvpCode(517);
pub const MEDIA_COMPONENT_NUMBER: AvpCode = AvpCode(518);
pub const MEDIA_SUB_COMPONENT: AvpCode = AvpCode(519);
pub const MEDIA_TYPE: AvpCode = AvpCode(520);
pub const FLOW_NUMBER: AvpCode = AvpCode(509);
pub const SPECIFIC_ACTION: AvpCode = AvpCode(513);
pub const FLOW_STATUS: AvpCode = AvpCode(511);

// Results
pub const DIAMETER_SUCCESS: ResultCode = ResultCode(2001);
pub const DIAMETER_COMMAND_UNSUPPORTED: ResultCode = ResultCode(3001);
pub const DIAMETER_UNABLE_TO_COMPLY: ResultCode = ResultCode(5012);
pub const DIAMETER_NO_COMMON_APPLICATION: ResultCode = ResultCode(5010);
pub const DIAMETER_CREDIT_LIMIT_REACHED: ResultCode = ResultCode(4012);
pub const DIAMETER_FIRST_REGISTRATION: ResultCode = ResultCode(2001);
pub const DIAMETER_SUBSEQUENT_REGISTRATION: ResultCode = ResultCode(2002);
pub const DIAMETER_ERROR_USER_UNKNOWN: ResultCode = ResultCode(5001);
pub const DIAMETER_SERVER_SELECTION: ResultCode = ResultCode(2003);
pub const DIAMETER_UNREGISTERED_SERVICE: ResultCode = ResultCode(2003);
pub const DIAMETER_ERROR_IDENTITIES_DONT_MATCH: ResultCode = ResultCode(5002);
pub const DIAMETER_ERROR_IDENTITY_NOT_REGISTERED: ResultCode = ResultCode(5003);
pub const DIAMETER_ERROR_ROAMING_NOT_ALLOWED: ResultCode = ResultCode(5004);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_convert_and_print_as_their_number() {
        assert_eq!(u32::from(CMD_DP), 282);
        assert_eq!(u32::from(APP_CX), APP_CX.get());
        assert_eq!(u32::from(DIAMETER_UNABLE_TO_COMPLY), 5012);
        assert_eq!((CMD_DP.to_string(), format!("{CMD_DP:?}")), ("282".to_string(), "CmdCode(282)".to_string()));
    }
}
