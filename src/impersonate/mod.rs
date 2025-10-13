#[doc(inline)]
pub use exec::*;
#[doc(inline)]
pub use privileges::*;

pub mod exec;
pub mod privileges;

/// Windows import

use windows_sys::{
    Win32::{
        Security::{
            SecurityImpersonation,
            SecurityDelegation,
            SecurityAnonymous,
            SecurityIdentification
        }
    },
};

use windows_sys::Win32::System::{
    SystemServices::{
        SECURITY_MANDATORY_LOW_RID,
        SECURITY_MANDATORY_MEDIUM_RID,
        SECURITY_MANDATORY_HIGH_RID,
        SECURITY_MANDATORY_SYSTEM_RID,
        SECURITY_MANDATORY_UNTRUSTED_RID,
        SECURITY_MANDATORY_PROTECTED_PROCESS_RID
    }
};

use crate::utils::FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID;
/// Code

#[repr(i32)]
pub enum ImpersonationLevel {
    Impersonation   = SecurityImpersonation,
    Delegation      = SecurityDelegation,
    Anonymous       = SecurityAnonymous,
    Identification  = SecurityIdentification,
}

impl ImpersonationLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            ImpersonationLevel::Impersonation   => "Impersonation",
            ImpersonationLevel::Delegation      => "Delegation",
            ImpersonationLevel::Anonymous       => "Anonymous",
            ImpersonationLevel::Identification  => "Identification",
        }
    }
}

#[repr(i32)]
pub enum IntegrityLevel {
    Untrusted        = SECURITY_MANDATORY_UNTRUSTED_RID,
    Low              = SECURITY_MANDATORY_LOW_RID,
    Medium           = SECURITY_MANDATORY_MEDIUM_RID,
    MediumPlus       = FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    High             = SECURITY_MANDATORY_HIGH_RID,
    System           = SECURITY_MANDATORY_SYSTEM_RID,
    ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
}

impl IntegrityLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            IntegrityLevel::Untrusted           => "Untrusted",
            IntegrityLevel::Low                 => "Low",
            IntegrityLevel::Medium              => "Medium",
            IntegrityLevel::MediumPlus          => "MediumPlus",
            IntegrityLevel::High                => "High",
            IntegrityLevel::System              => "System",
            IntegrityLevel::ProtectedProcess    => "ProtectedProcess",
        }
    }
}