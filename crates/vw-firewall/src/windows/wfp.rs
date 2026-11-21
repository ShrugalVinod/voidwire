//! WFP executor: converts `windows_spec::FilterSpec` into `FWPM_FILTER0`
//! and applies the whole set in one BFE transaction.

use std::ffi::c_void;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use vw_core::{Result, VwError};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFilterGetByKey0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6, FWPM_PROVIDER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_OVERLAPPING, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::plan::{FirewallStatus, LockdownPlan};
use crate::windows_spec::{
    self, block_all_key, boot_time_keys, Condition, FilterAction, FilterSpec, Layer, PROVIDER_KEY,
    SUBLAYER_KEY, SUBLAYER_WEIGHT,
};
use crate::FirewallBackend;

// The pure model mirrors these flag values; keep them in lock-step.
const _: () = assert!(
    windows_spec::FWPM_FILTER_FLAG_PERSISTENT
        == windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_PERSISTENT
);
const _: () = assert!(
    windows_spec::FWPM_FILTER_FLAG_BOOTTIME
        == windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_BOOTTIME
);

const ENUM_BATCH: u32 = 128;

fn guid(k: u128) -> GUID {
    GUID::from_u128(k)
}

fn guid_u128(g: &GUID) -> u128 {
    (u128::from(g.data1) << 96)
        | (u128::from(g.data2) << 80)
        | (u128::from(g.data3) << 64)
        | u128::from(u64::from_be_bytes(g.data4))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn hr(code: windows_sys::core::HRESULT) -> u32 {
    code as u32
}

fn check(rc: u32, what: &str) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(VwError::Firewall(format!("{what} failed: 0x{rc:08x}")))
    }
}

fn check_allow(rc: u32, what: &str, allowed: u32) -> Result<()> {
    if rc == allowed {
        Ok(())
    } else {
        check(rc, what)
    }
}

pub(crate) fn layer_guid(l: Layer) -> GUID {
    match l {
        Layer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::AleAuthRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::AleAuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        Layer::OutboundTransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        Layer::OutboundTransportV6 => FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
    }
}

/// An open, non-dynamic BFE session (objects outlive it).
struct Engine(HANDLE);

impl Engine {
    fn open() -> Result<Self> {
        let mut name = wide("VoidWire lockdown session");
        let mut session = FWPM_SESSION0::default();
        session.displayData.name = name.as_mut_ptr();
        session.flags = 0; // not FWPM_SESSION_FLAG_DYNAMIC: filters persist
        session.txnWaitTimeoutInMSec = 10_000;
        let mut h: HANDLE = ptr::null_mut();
        // SAFETY: all pointers are valid for the duration of the call; `name`
        // outlives it, a null server name selects the local BFE, and `h`
        // receives the engine handle owned by the returned `Engine`.
        let rc = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut h,
            )
        };
        check(rc, "FwpmEngineOpen0")?;
        Ok(Self(h))
    }

    fn begin(&self) -> Result<Txn<'_>> {
        // SAFETY: `self.0` is a valid engine handle for the lifetime of `self`.
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "FwpmTransactionBegin0",
        )?;
        Ok(Txn {
            engine: self,
            done: false,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by FwpmEngineOpen0 and is closed once.
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

/// A read/write BFE transaction; aborted on drop unless committed.
struct Txn<'a> {
    engine: &'a Engine,
    done: bool,
}

impl Txn<'_> {
    fn commit(mut self) -> Result<()> {
        self.done = true;
        // SAFETY: valid engine handle with an open transaction.
        check(
            unsafe { FwpmTransactionCommit0(self.engine.0) },
            "FwpmTransactionCommit0",
        )
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.done {
            // SAFETY: valid engine handle with an open transaction.
            unsafe {
                FwpmTransactionAbort0(self.engine.0);
            }
        }
    }
}

/// App-id blob allocated by `FwpmGetAppIdFromFileName0`.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn from_path(p: &Path) -> Result<Self> {
        let w = wide_path(p);
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: `w` is a NUL-terminated wide string alive for the call and
        // `blob` receives a BFE allocation released in `Drop`.
        let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
        check(rc, "FwpmGetAppIdFromFileName0")?;
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from FwpmGetAppIdFromFileName0 and is
            // freed exactly once with the matching allocator.
            unsafe { FwpmFreeMemory0(&mut self.0 as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
        }
    }
}

/// Owns everything a condition value points to until `FwpmFilterAdd0` returns.
/// Boxes keep addresses stable while the vectors grow.
#[allow(clippy::vec_box)] // the Box is what makes the pointers stable
#[derive(Default)]
struct Arena {
    u64s: Vec<Box<u64>>,
    arr16: Vec<Box<FWP_BYTE_ARRAY16>>,
    m4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    m6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    app_ids: Vec<AppId>,
}

fn cv(ty: i32, v: FWP_CONDITION_VALUE0_0) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: ty,
        Anonymous: v,
    }
}

fn condition(c: &Condition, a: &mut Arena) -> Result<FWPM_FILTER_CONDITION0> {
    let (field, match_type, value) = match c {
        Condition::Loopback => (
            FWPM_CONDITION_FLAGS,
            FWP_MATCH_FLAGS_ALL_SET,
            cv(
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            ),
        ),
        Condition::LocalInterface(luid) => {
            let mut b = Box::new(*luid);
            let p: *mut u64 = &mut *b;
            a.u64s.push(b);
            (
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                FWP_MATCH_EQUAL,
                cv(FWP_UINT64, FWP_CONDITION_VALUE0_0 { uint64: p }),
            )
        }
        Condition::AppId(path) => {
            let id = AppId::from_path(path)?;
            let p = id.0;
            a.app_ids.push(id);
            (
                FWPM_CONDITION_ALE_APP_ID,
                FWP_MATCH_EQUAL,
                cv(FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0_0 { byteBlob: p }),
            )
        }
        Condition::RemoteAddr(IpAddr::V4(v4)) => (
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_MATCH_EQUAL,
            cv(
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: u32::from(*v4),
                },
            ),
        ),
        Condition::RemoteAddr(IpAddr::V6(v6)) => {
            let mut b = Box::new(FWP_BYTE_ARRAY16 {
                byteArray16: v6.octets(),
            });
            let p: *mut FWP_BYTE_ARRAY16 = &mut *b;
            a.arr16.push(b);
            (
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_MATCH_EQUAL,
                cv(
                    FWP_BYTE_ARRAY16_TYPE,
                    FWP_CONDITION_VALUE0_0 { byteArray16: p },
                ),
            )
        }
        Condition::RemoteNet(net) => match net.addr() {
            IpAddr::V4(v4) => {
                let mut b = Box::new(FWP_V4_ADDR_AND_MASK {
                    addr: u32::from(v4),
                    mask: net.v4_mask(),
                });
                let p: *mut FWP_V4_ADDR_AND_MASK = &mut *b;
                a.m4.push(b);
                (
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    cv(FWP_V4_ADDR_MASK, FWP_CONDITION_VALUE0_0 { v4AddrMask: p }),
                )
            }
            IpAddr::V6(v6) => {
                let mut b = Box::new(FWP_V6_ADDR_AND_MASK {
                    addr: v6.octets(),
                    prefixLength: net.prefix(),
                });
                let p: *mut FWP_V6_ADDR_AND_MASK = &mut *b;
                a.m6.push(b);
                (
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    cv(FWP_V6_ADDR_MASK, FWP_CONDITION_VALUE0_0 { v6AddrMask: p }),
                )
            }
        },
        Condition::RemotePort(port) => (
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_MATCH_EQUAL,
            cv(FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: *port }),
        ),
        Condition::LocalPort(port) => (
            FWPM_CONDITION_IP_LOCAL_PORT,
            FWP_MATCH_EQUAL,
            cv(FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: *port }),
        ),
        Condition::Protocol(p) => (
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_MATCH_EQUAL,
            cv(FWP_UINT8, FWP_CONDITION_VALUE0_0 { uint8: *p }),
        ),
    };
    Ok(FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        conditionValue: value,
    })
}

fn add_filter(e: &Engine, spec: &FilterSpec) -> Result<()> {
    let mut arena = Arena::default();
    let mut conds = spec
        .conditions
        .iter()
        .map(|c| condition(c, &mut arena))
        .collect::<Result<Vec<_>>>()?;
    let mut name = wide(&spec.name);
    let mut provider = guid(PROVIDER_KEY);
    let mut f = FWPM_FILTER0 {
        filterKey: guid(spec.key),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        flags: spec.flags(),
        layerKey: layer_guid(spec.layer),
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: spec.weight },
        },
        numFilterConditions: conds.len() as u32,
        filterCondition: if conds.is_empty() {
            ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        },
        ..Default::default()
    };
    f.action.r#type = match spec.action {
        FilterAction::Permit => FWP_ACTION_PERMIT,
        FilterAction::Block => FWP_ACTION_BLOCK,
    };
    if spec.in_our_sublayer() {
        f.providerKey = &mut provider;
        f.subLayerKey = guid(SUBLAYER_KEY);
    }
    let mut id = 0u64;
    // SAFETY: `f` and everything it points to (`name`, `provider`, `conds`
    // and the values owned by `arena`) stay alive until the call returns;
    // a null security descriptor selects the BFE default.
    let rc = unsafe { FwpmFilterAdd0(e.0, &f, ptr::null_mut(), &mut id) };
    check(rc, "FwpmFilterAdd0")
}

fn ensure_provider(e: &Engine) -> Result<()> {
    let mut name = wide("VoidWire");
    let mut desc = wide("VoidWire fail-closed lockdown");
    let p = FWPM_PROVIDER0 {
        providerKey: guid(PROVIDER_KEY),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: desc.as_mut_ptr(),
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        ..Default::default()
    };
    // SAFETY: `p` and its strings outlive the call.
    let rc = unsafe { FwpmProviderAdd0(e.0, &p, ptr::null_mut()) };
    check_allow(rc, "FwpmProviderAdd0", hr(FWP_E_ALREADY_EXISTS))
}

fn ensure_sublayer(e: &Engine) -> Result<()> {
    let mut name = wide("VoidWire lockdown");
    let mut desc = wide("VoidWire Iron Dome default-deny filters");
    let mut provider = guid(PROVIDER_KEY);
    let s = FWPM_SUBLAYER0 {
        subLayerKey: guid(SUBLAYER_KEY),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: desc.as_mut_ptr(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider,
        weight: SUBLAYER_WEIGHT,
        ..Default::default()
    };
    // SAFETY: `s` and everything it points to outlive the call.
    let rc = unsafe { FwpmSubLayerAdd0(e.0, &s, ptr::null_mut()) };
    check_allow(rc, "FwpmSubLayerAdd0", hr(FWP_E_ALREADY_EXISTS))
}

/// Keys of every filter of our provider that sits in our sublayer.
fn our_filter_keys(e: &Engine) -> Result<Vec<GUID>> {
    let mut provider = guid(PROVIDER_KEY);
    let mut keys = Vec::new();
    for layer in Layer::ALL {
        let tmpl = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider,
            layerKey: layer_guid(layer),
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            actionMask: 0xFFFF_FFFF,
            ..Default::default()
        };
        let mut h: HANDLE = ptr::null_mut();
        // SAFETY: `tmpl` (and `provider`) outlive the call; `h` receives an
        // enumeration handle destroyed below.
        let rc = unsafe { FwpmFilterCreateEnumHandle0(e.0, &tmpl, &mut h) };
        if rc == hr(FWP_E_PROVIDER_NOT_FOUND) {
            continue;
        }
        check(rc, "FwpmFilterCreateEnumHandle0")?;
        let result = (|| -> Result<()> {
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut n = 0u32;
                // SAFETY: valid engine + enum handles; BFE allocates `entries`.
                let rc = unsafe { FwpmFilterEnum0(e.0, h, ENUM_BATCH, &mut entries, &mut n) };
                check(rc, "FwpmFilterEnum0")?;
                for i in 0..n as usize {
                    // SAFETY: BFE returned `n` valid filter pointers.
                    let f = unsafe { &**entries.add(i) };
                    if guid_u128(&f.subLayerKey) == SUBLAYER_KEY {
                        keys.push(f.filterKey);
                    }
                }
                if !entries.is_null() {
                    // SAFETY: `entries` was allocated by FwpmFilterEnum0 and
                    // is released exactly once; keys were copied out.
                    unsafe {
                        FwpmFreeMemory0(
                            &mut entries as *mut *mut *mut FWPM_FILTER0 as *mut *mut c_void,
                        )
                    };
                }
                if n < ENUM_BATCH {
                    return Ok(());
                }
            }
        })();
        // SAFETY: `h` is the handle created above, destroyed once.
        unsafe { FwpmFilterDestroyEnumHandle0(e.0, h) };
        result?;
    }
    Ok(keys)
}

fn delete_filter(e: &Engine, key: &GUID) -> Result<()> {
    // SAFETY: `key` points to a valid GUID for the duration of the call.
    let rc = unsafe { FwpmFilterDeleteByKey0(e.0, key) };
    check_allow(rc, "FwpmFilterDeleteByKey0", hr(FWP_E_FILTER_NOT_FOUND))
}

fn filter_exists(e: &Engine, key: u128) -> Result<bool> {
    let g = guid(key);
    let mut f: *mut FWPM_FILTER0 = ptr::null_mut();
    // SAFETY: `g` is valid for the call; on success BFE allocates `f`.
    let rc = unsafe { FwpmFilterGetByKey0(e.0, &g, &mut f) };
    if rc == hr(FWP_E_FILTER_NOT_FOUND) {
        return Ok(false);
    }
    check(rc, "FwpmFilterGetByKey0")?;
    if !f.is_null() {
        // SAFETY: `f` was allocated by FwpmFilterGetByKey0; freed once.
        unsafe { FwpmFreeMemory0(&mut f as *mut *mut FWPM_FILTER0 as *mut *mut c_void) };
    }
    Ok(true)
}

/// Remove all our filters (persistent set by enumeration, boot-time set by key).
fn delete_all(e: &Engine) -> Result<()> {
    for k in our_filter_keys(e)? {
        delete_filter(e, &k)?;
    }
    for k in boot_time_keys() {
        delete_filter(e, &guid(k))?;
    }
    Ok(())
}

/// WFP backend. Holds no OS handles between calls (each operation opens its
/// own BFE session), so it is `Send`.
#[derive(Debug, Default)]
pub struct WfpBackend {
    plan: Option<LockdownPlan>,
}

impl WfpBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn apply(&mut self, plan: &LockdownPlan) -> Result<()> {
        plan.validate()?;
        let specs = windows_spec::render(plan);
        let engine = Engine::open()?;
        let txn = engine.begin()?;
        ensure_provider(&engine)?;
        ensure_sublayer(&engine)?;
        // Old and new sets are swapped inside one transaction: no gap.
        delete_all(&engine)?;
        for s in &specs {
            add_filter(&engine, s)?;
        }
        txn.commit()?;
        tracing::debug!(filters = specs.len(), "WFP lockdown committed");
        self.plan = Some(plan.clone());
        Ok(())
    }
}

impl FirewallBackend for WfpBackend {
    fn name(&self) -> &'static str {
        "wfp"
    }

    fn arm(&mut self, plan: &LockdownPlan) -> Result<()> {
        self.apply(plan)
    }

    fn update(&mut self, plan: &LockdownPlan) -> Result<()> {
        self.apply(plan)
    }

    fn disarm(&mut self) -> Result<()> {
        let engine = Engine::open()?;
        let txn = engine.begin()?;
        delete_all(&engine)?;
        let sub = guid(SUBLAYER_KEY);
        // SAFETY: `sub` is valid for the call.
        let rc = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &sub) };
        check_allow(rc, "FwpmSubLayerDeleteByKey0", hr(FWP_E_SUBLAYER_NOT_FOUND))?;
        let prov = guid(PROVIDER_KEY);
        // SAFETY: `prov` is valid for the call.
        let rc = unsafe { FwpmProviderDeleteByKey0(engine.0, &prov) };
        check_allow(rc, "FwpmProviderDeleteByKey0", hr(FWP_E_PROVIDER_NOT_FOUND))?;
        txn.commit()?;
        self.plan = None;
        tracing::debug!("WFP lockdown removed");
        Ok(())
    }

    fn status(&self) -> Result<FirewallStatus> {
        let armed = self.is_armed_in_kernel()?;
        // WFP default-deny is independent of the routing table, so rogue
        // DHCP routes cannot bypass it (Tunnelvision guard = armed).
        Ok(FirewallStatus::from_plan(
            self.name(),
            self.plan.as_ref(),
            armed,
            armed,
        ))
    }

    fn is_armed_in_kernel(&self) -> Result<bool> {
        let engine = Engine::open()?;
        for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
            if !filter_exists(&engine, block_all_key(layer))? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
