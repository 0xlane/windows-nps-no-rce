use windows::{Win32::NetworkManagement::NetworkPolicyServer::RADIUS_EXTENSION_POINT, core::PCWSTR};

pub const CLSID_IASExtentionHost: windows::core::GUID = windows::core::GUID::from_u128(0x8C334A55_DDB9_491C_817E_35A6B85D2ECB);
#[derive(Debug)]
#[repr(transparent)]
pub struct IIASExtentionHost(windows::core::IUnknown);
impl IIASExtentionHost {
    pub unsafe fn Initialize(&self, p0: RADIUS_EXTENSION_POINT, p1: u32, p2: PCWSTR) -> Result<(), windows::core::Error> {
        (::windows::core::Interface::vtable(self).Initialize)(windows::core::Interface::as_raw(self), ::std::mem::transmute(p0), ::std::mem::transmute(p1), ::std::mem::transmute(p2)).ok()
    }
}
unsafe impl windows::core::ComInterface for IIASExtentionHost {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x7469ae5e_1ca1_4181_970c_bdfd8eaa2c4f);
}
unsafe impl windows::core::Interface for IIASExtentionHost {
    type Vtable = IIASExtensionHost_Vtbl;
}
impl ::core::clone::Clone for IIASExtentionHost {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[repr(C)]
pub struct IIASExtensionHost_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub Initialize: unsafe extern "system" fn(this: *mut ::core::ffi::c_void, p0: RADIUS_EXTENSION_POINT, p1: u32, p2: PCWSTR) -> windows::core::HRESULT,
}