// A lot of this code is derived from https://github.com/trailofbits/appjaillauncher-rs
// There are other approaches (minor variations) that I struggled with prior settling on this code
extern crate winapi;

use winapi::um::combaseapi::CoInitializeEx;
use winapi::um::objbase::COINIT_APARTMENTTHREADED;
use winapi::um::winnt::GENERIC_READ;

use std::{
    env,
    ffi::{OsStr, OsString},
    iter::once,
    mem,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::Path,
    ptr,
    sync::Once
};

use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{BOOL, DWORD, FALSE, LPVOID},
        ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT, MAKELANGID, LPWSTR},
        sddl::{ConvertSidToStringSidW, ConvertStringSidToSidW},
        winerror,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi,
        processthreadsapi::{
            CreateProcessW, GetExitCodeProcess, InitializeProcThreadAttributeList,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, UpdateProcThreadAttribute,
        },
        securitybaseapi::{
            AddAccessAllowedAce, AddAccessDeniedAce, GetAce, GetFileSecurityW,
            GetLengthSid, GetSecurityDescriptorDacl, InitializeAcl, FreeSid,
            InitializeSecurityDescriptor, SetFileSecurityW, SetSecurityDescriptorDacl,
        },
        synchapi::WaitForSingleObject,
        userenv::{
            CreateAppContainerProfile, DeleteAppContainerProfile,
            DeriveAppContainerSidFromAppContainerName,
        },
        winbase::{
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, FormatMessageW,
            FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS, INFINITE, LocalFree, STARTUPINFOEXW,
        },
        winnt::{
            ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACL, ACL_REVISION,
            DACL_SECURITY_INFORMATION, LPCWSTR, PACL, PACE_HEADER,
            PSECURITY_DESCRIPTOR, PSID, PSID_AND_ATTRIBUTES, SECURITY_CAPABILITIES,
            SECURITY_DESCRIPTOR_MIN_LENGTH, SECURITY_DESCRIPTOR_REVISION,
        },
    },
};

pub type AclEntryType = u8;

static START: Once = Once::new();
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 131081;

#[derive(Debug)]
pub enum SandboxError {
    CreateAppContainerProfileCommandFailed(String),
    CreateAppContainerProfileFailed(String),
    RunAppContainerFailed(String),
    DeleteAppContainerProfileFailed(String),
    AceOperationFailed(String),
    SidConversionFailed(String)
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::CreateAppContainerProfileCommandFailed(message) => {
                write!(f,"Could not create AppContainerProfile command! {}", message)
            }
            SandboxError::CreateAppContainerProfileFailed(message) => {
                write!(f, "Could not create AppContainerProfile! {}", message)
            }
            SandboxError::RunAppContainerFailed(message) => {
                write!(f, "Could not run AppContainer! {}", message)
            }
            SandboxError::DeleteAppContainerProfileFailed(message) => {
                write!(f, "Could not delete AppContainer! {}", message)
            },
            SandboxError::AceOperationFailed(message) => {
                write!(f, "Could not perform ACL entry operation! {}", message)
            },
            SandboxError::SidConversionFailed(message) => {
                write!(f, "Could not perform SID transformation! {}", message)
            }
        }
    }
}

impl std::error::Error for SandboxError {}

const MAX_LENGTH_APPCONTAINER_NAME: usize = 64;
const MAX_LENGTH_DISPLAY_NAME: usize      = 512;
const MAX_LENGTH_DESCRIPTION: usize       = 2048;

#[derive(Debug)]
pub struct CreateAppContainerProfileCommand {
    pub appcontainer_name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug)]
struct SidPtr {
    raw_ptr: PSID,    
}

impl SidPtr {
    fn new(ptr: PSID) -> SidPtr {
        SidPtr { raw_ptr: ptr }
    }
}

impl Drop for SidPtr {
    fn drop(&mut self) {
        if self.raw_ptr != (0 as PSID) {
            unsafe {
                FreeSid(self.raw_ptr);
            }
        }
    }
}

#[derive(Debug)]
pub struct AppContainerProfile {
    p_sid: SidPtr,
}

impl CreateAppContainerProfileCommand {
    pub fn new(appcontainer_name: String, display_name: Option<String>, description: Option<String>) -> Result<Self, SandboxError> {
        if appcontainer_name.len() == 0 || appcontainer_name.trim().len() == 0 {
            return Err(SandboxError::CreateAppContainerProfileCommandFailed("The appcontainer name must not be empty!".to_string()));
        }

        if appcontainer_name.len() > MAX_LENGTH_APPCONTAINER_NAME {
            return Err(SandboxError::CreateAppContainerProfileCommandFailed(format!("The appcontainer name must not exceed {} characters!", MAX_LENGTH_APPCONTAINER_NAME)));
        }

        if let Some(ref displayed_name) = display_name {
            if displayed_name.len() > MAX_LENGTH_DISPLAY_NAME {
                return Err(SandboxError::CreateAppContainerProfileCommandFailed(format!("The display_name must not exceed {} characters!", MAX_LENGTH_DISPLAY_NAME)));
            }
        }

        if let Some(ref summary) = description {
            if summary.len() > MAX_LENGTH_DESCRIPTION {
                return Err(SandboxError::CreateAppContainerProfileCommandFailed(format!("The description must not exceed {} characters!", MAX_LENGTH_DESCRIPTION)));
            }
        }

        Ok(Self {
            appcontainer_name,
            display_name,
            description,
        })
    }
}

fn get_dacl(path: &str) -> Result<(Vec<u8>, PACL), SandboxError> {
    let wpath: Vec<u16> = str_to_u16(path);
    let mut buff_size: DWORD = 0;
    let mut status = unsafe {
        GetFileSecurityW(wpath.as_ptr(),
                         DACL_SECURITY_INFORMATION,
                         ptr::null_mut(),
                         0,
                         &mut buff_size)
    };
    if status != 0 {
        return Err(SandboxError::AceOperationFailed(format!("Could not retrieve security information size for file '{}'! {}", path, get_last_error_as_string())));
    }

    let mut security_desc: Vec<u8> = Vec::with_capacity(buff_size as usize);
    status = unsafe {
        GetFileSecurityW(wpath.as_ptr(),
                         DACL_SECURITY_INFORMATION,
                         security_desc.as_mut_ptr() as LPVOID,
                         buff_size,
                         &mut buff_size)
    };

    if status == 0 {
        return Err(SandboxError::AceOperationFailed(format!("Could not retrieve security information details for file '{}'! {}", path, get_last_error_as_string())));
    }

    let mut p_dacl: PACL = 0 as PACL;
    let mut dacl_present: BOOL = 0;
    let mut dacl_default: BOOL = 0;

    let status = unsafe {
        GetSecurityDescriptorDacl(security_desc.as_ptr() as PSECURITY_DESCRIPTOR,
                                  &mut dacl_present,
                                  &mut p_dacl,
                                  &mut dacl_default)
    };

    if status == 0 || dacl_present == 0 {
        return Err(SandboxError::AceOperationFailed(format!("Could not retrieve security descriptor for file '{}'! {}", path, get_last_error_as_string())));
    }

    Ok((security_desc, p_dacl))
}

macro_rules! add_entry {
    ($z: ident, $x: ident => $y: path) => {
        {
            let entry: *mut $y = $x as *mut $y;
            let sid_offset = mem::offset_of!($y, SidStart);
            let sid_ptr = unsafe { (entry as *mut u8).add(sid_offset) as PSID };

            $z.push(Ace {
                entry_type: unsafe { (*$x).AceType },
                flags: unsafe { (*$x).AceFlags },
                mask: unsafe { (*entry).Mask },
                sid: sid_to_string(sid_ptr)?,
            })
        }
    };
}

pub const ACCESS_ALLOWED: u8 = 0;
pub const ACCESS_DENIED: u8  = 1;

pub struct Ace {
    pub entry_type: u8,
    #[allow(dead_code)]
    pub flags: u8,
    pub mask: u32,
    pub sid: String,
}

pub struct Dacl {
    entries: Vec<Ace>,
}

impl Dacl {

    pub fn from_path(path: &str) -> Result<Self, SandboxError> {
        // Important we need to keep security descriptor info around in memory...
        #[allow(unused_variables)]
        let (sec_desc, p_dacl) = get_dacl(path)?;

        let mut hdr = ptr::null_mut();
        let mut entries: Vec<Ace> = Vec::new();
        
        for i in 0..unsafe { (*p_dacl).AceCount } {
            if unsafe { GetAce(p_dacl, i as u32, &mut hdr) } == 0 {
                return Err(SandboxError::AceOperationFailed(format!("Could not retrieve access control entries for file '{}'! {}", path, get_last_error_as_string())));
            }

            let hdr = hdr as PACE_HEADER;
            let ace_type = unsafe { (*hdr).AceType };

            if ace_type == ACCESS_ALLOWED {
                add_entry!(entries, hdr => ACCESS_ALLOWED_ACE);
            } else if ace_type == ACCESS_DENIED{
                add_entry!(entries, hdr => ACCESS_DENIED_ACE);
            } else {
                return Err(SandboxError::AceOperationFailed(format!("Unknown access control entry type with value '{}' found!", ace_type)));
            }
        }

        Ok(Self { entries: entries })
    }

    #[allow(dead_code)]
    pub fn get_entries(&self) -> &Vec<Ace> {
        &self.entries
    }

    pub fn add_entry(&mut self, entry: Ace) -> bool {
        let target: usize;
        match entry.entry_type {
            ACCESS_ALLOWED => {
                // We are assuming that the list is proper: that denied ACEs are placed
                // prior to allow ACEs
                match self.entries.iter().position(|&ref x| x.entry_type != ACCESS_DENIED) {
                    Some(x) => {
                        target = x;
                    }
                    None => {
                        target = 0xffffffff;
                    }
                }
            }
            ACCESS_DENIED => {
                target = 0;
            }
            _ => return false,
        }

        match string_to_sid(&entry.sid) {
            Err(_) => return false,
            Ok(_) => {}
        }

        if self.entries
            .iter()
            .any(|x| x.sid == entry.sid && x.entry_type == entry.entry_type) {
                return false;
            }

        if target == 0xffffffff {
            self.entries.push(entry)
        } else {
            self.entries.insert(target, entry)
        }

        true
    }

    pub fn entry_exists(&self, sid: &str, entry_type: AclEntryType) -> Option<usize> {
        let index = match self.entries
            .iter()
            .position(|x| x.sid == sid && x.entry_type == entry_type) {
                Some(x) => x,
                _ => return None,
            };

        Some(index)
    }

    pub fn remove_entry(&mut self, sid: &str, entry_type: AclEntryType) -> bool {
        if let Some(index) = self.entry_exists(sid, entry_type) {
            self.entries.remove(index);
            return true;
        }

        false
    }

    pub fn apply_to_path(&self, path: &str) -> Result<(), SandboxError> {
        let wpath: Vec<u16> = str_to_u16(path);
        let mut security_desc: Vec<u8> = Vec::with_capacity(SECURITY_DESCRIPTOR_MIN_LENGTH);

        if unsafe {
            InitializeSecurityDescriptor(security_desc.as_mut_ptr() as LPVOID,
                                         SECURITY_DESCRIPTOR_REVISION)
        } == 0 {
            return Err(SandboxError::AceOperationFailed(format!("Could not initialize security descriptor for file '{}'! {}", path, get_last_error_as_string())));
        }

        let mut acl_size = mem::size_of::<ACL>();
        for entry in &self.entries {
            let sid = string_to_sid(&entry.sid)?;
            acl_size += unsafe { GetLengthSid(sid.raw_ptr) } as usize;

            let entry_type = entry.entry_type;

            if entry.entry_type == ACCESS_ALLOWED {
                acl_size += mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<DWORD>();
            } else if entry.entry_type == ACCESS_DENIED {
                acl_size += mem::size_of::<ACCESS_DENIED_ACE>() - mem::size_of::<DWORD>();
            } else {
                return Err(SandboxError::AceOperationFailed(format!("Could not compute ACL size due to entry with type '{}'!", entry_type)));
            }
        }

        let mut acl_buffer: Vec<u8> = Vec::with_capacity(acl_size);
        if unsafe {
            InitializeAcl(acl_buffer.as_mut_ptr() as PACL,
                          acl_size as DWORD,
                          ACL_REVISION as u32)
        } == 0 {
            return Err(SandboxError::AceOperationFailed(format!("Could not initialize ACL for file: '{}'! {}", path, get_last_error_as_string())));
        }

        for entry in &self.entries {
            let sid = string_to_sid(&entry.sid)?;

            if entry.entry_type == 0 {
                if unsafe {
                    AddAccessAllowedAce(acl_buffer.as_mut_ptr() as PACL,
                                        ACL_REVISION as u32,
                                        entry.mask,
                                        sid.raw_ptr)
                } == 0 {
                    return Err(SandboxError::AceOperationFailed(format!("Could not add allowed ACE entries! {}", get_last_error_as_string())));
                }
            } else if entry.entry_type == 1 {
                if unsafe {
                    AddAccessDeniedAce(acl_buffer.as_mut_ptr() as PACL,
                                       ACL_REVISION as u32,
                                       entry.mask,
                                       sid.raw_ptr)
                } == 0 {
                    return Err(SandboxError::AceOperationFailed(format!("Could not add denied ACE entries! {}", get_last_error_as_string())));
                }
            } else {
                return Err(SandboxError::AceOperationFailed(format!("Could not operate on entry with type '{}'!", entry.entry_type)));
            }
        }

        if unsafe {
            SetSecurityDescriptorDacl(security_desc.as_mut_ptr() as PSECURITY_DESCRIPTOR,
                                      1,
                                      acl_buffer.as_ptr() as PACL,
                                      0)
        } == 0 {
            return Err(SandboxError::AceOperationFailed(format!("Failed to set security descriptor for file '{}'! {}", path, get_last_error_as_string())));
        }

        if unsafe {
            SetFileSecurityW(wpath.as_ptr(),
                             DACL_SECURITY_INFORMATION,
                             security_desc.as_ptr() as PSECURITY_DESCRIPTOR)
        } == 0 {
            return Err(SandboxError::AceOperationFailed(format!("Failed to set file security details for file '{}'! {}", path, get_last_error_as_string())));
        }

        Ok(())
    }
}


#[derive(Debug, Clone)]
pub struct Program {
    pub executable: String,
    pub current_dir: Option<String>,
    parameters: Vec<String>,
}

impl Program {
    pub fn new(executable: String, current_dir: Option<String>) -> Self {
        Self {
            executable: executable,
            current_dir: current_dir,
            parameters: vec![],
        }
    }

    pub fn add_parameter(&mut self, parameter: String) {
        self.parameters.push(parameter);
    }

    pub fn parameters(self) -> String {
        self.parameters.join(" ")
    }
}

pub fn create_appcontainer_profile(
    create_appcontainer_profile_command: CreateAppContainerProfileCommand,
) -> Result<AppContainerProfile, SandboxError> {
    let mut p_sid: PSID = 0 as PSID;
    let mut creation_error: Option<SandboxError> = None;
    let profile_name = str_to_u16(&(create_appcontainer_profile_command.appcontainer_name));

    let display_name_ptr =
        if let Some(ref displayed_name) = create_appcontainer_profile_command.display_name {
            let ret = str_to_u16(displayed_name);
            ret.as_ptr()
        } else {
            ptr::null_mut()
        };

    let description_ptr =
        if let Some(ref described) = create_appcontainer_profile_command.description {
            let ret = str_to_u16(described);
            ret.as_ptr()
        } else {
            ptr::null_mut()
        };

    let hr = unsafe {
        CreateAppContainerProfile(profile_name.as_ptr(),
                                  display_name_ptr,
                                  description_ptr,
                                  0 as PSID_AND_ATTRIBUTES,
                                  0 as DWORD,
                                  &mut p_sid)
    };

    if hr != winerror::S_OK {
        if hr == winerror::E_ACCESSDENIED {
            creation_error = Some(SandboxError::CreateAppContainerProfileFailed(
                "Missing permissions to create an AppContainer profile.".to_string(),
            ));
        } else if hr == winerror::E_INVALIDARG {
            creation_error = Some(SandboxError::CreateAppContainerProfileFailed("The container name is NULL, or the container name, the display name, or the description strings exceed their specified respective limits for length.".to_string()));
        } else {
            if hr == winerror::HRESULT_FROM_WIN32(winerror::ERROR_ALREADY_EXISTS) {
                let hr = unsafe {
                    DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut p_sid)
                };

                if hr != (winerror::ERROR_SUCCESS as i32) {
                    creation_error = Some(SandboxError::CreateAppContainerProfileFailed("The data store for the appcontainer already exists and we could not retrieve its details!".to_string()));
                }
            } else {
                creation_error = Some(SandboxError::CreateAppContainerProfileFailed(get_last_error_as_string()));
            }
        }
    }

    if let Some(failure) = creation_error {
        unsafe { FreeSid(p_sid); }

        return Err(failure);
    }

    return Ok(AppContainerProfile {
        p_sid: SidPtr { raw_ptr: p_sid },
    });
}

fn string_to_sid(string_sid: &str) -> Result<SidPtr, SandboxError> {
    // Convert the Rust str to a null-terminated wide string
    let wide: Vec<u16> = str_to_u16(string_sid);
    let mut psid: PSID = ptr::null_mut();
    let success = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut psid as *mut LPVOID) };

    if success != 0 {
        Ok(SidPtr::new(psid))
    } else {
        Err(SandboxError::SidConversionFailed(format!("Could not convert String '{}' to SID pointer! {}", string_sid, get_last_error_as_string())))
    }
}

fn sid_to_string(psid: PSID) -> Result<String, SandboxError> {
    let mut string_sid_ptr: LPWSTR = ptr::null_mut();

    if unsafe { ConvertSidToStringSidW(psid, &mut string_sid_ptr) } == 0 {
        return Err(SandboxError::SidConversionFailed(format!("Could not convert SID pointer to string! {}", get_last_error_as_string())));
    }

    unsafe {
        let mut len = 0;
        while *string_sid_ptr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(string_sid_ptr, len);
        let sid_string = OsString::from_wide(slice).to_string_lossy().into_owned();

        LocalFree(string_sid_ptr as LPVOID);
        Ok(sid_string)
    }
}

pub fn run_appcontainer(
    appcontainer_profile: AppContainerProfile,
    program: Program        
) -> Result<u32, SandboxError> {
    // Set up the process creation attributes with AppContainer SID
    let p_sid = appcontainer_profile.p_sid.raw_ptr;

    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: p_sid,
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };

    let mut list_size: SIZE_T = 0;

    unsafe { // Obtain the list size for thread attributes
        if InitializeProcThreadAttributeList(0 as LPPROC_THREAD_ATTRIBUTE_LIST, 1, 0, &mut list_size) != 0 {
            return Err(SandboxError::RunAppContainerFailed(format!("First initialization of process thread attribute list failed! {}", get_last_error_as_string())));
        }
    }

    let mut attr_buf = Vec::with_capacity(list_size as usize);

    unsafe { // Initialize thread attributes with the allocated list
        if InitializeProcThreadAttributeList(attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST, 1, 0, &mut list_size) == 0 {
            return Err(SandboxError::RunAppContainerFailed(format!("Second initialization of process thread attribute list failed! {}", get_last_error_as_string())));
        }
    }

    unsafe {
        if UpdateProcThreadAttribute(attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST,
                                     0,
                                     PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                     &mut capabilities as *mut _ as LPVOID,
                                     mem::size_of::<SECURITY_CAPABILITIES>(),
                                     ptr::null_mut(),
                                     ptr::null_mut()) == 0 {
            return Err(SandboxError::RunAppContainerFailed(format!("UpdateProcThreadAttribute failed: {}", get_last_error_as_string())));
        }
    }

    let mut si_ex: STARTUPINFOEXW = unsafe {
        mem::zeroed()
    };
    si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;

    // Here you can configure additional startup parameters if needed
    let program_location = program.executable.clone();
    let program_parameters = program.clone().parameters();

    println!("Program params: {}", &program_parameters);
    // Obtain a pointer to the program and its argument
    let app_name_w: Vec<u16> = str_to_u16(&program_location);
    let params_w = {
        if program_parameters.trim().len() != 0 {
            let quoted_params = format!("\"{}\"", program_parameters); 
            let prog_params_data = str_to_u16(&quoted_params);
            prog_params_data.as_ptr() as *mut u16
        } else {
            ptr::null_mut()
        }
    };

    // Obtain a pointer to the working directory for the program execution
    let current_dir = {
        if let Some(ref p) = program.current_dir {
            let pp = p.clone();
            let current_loc_w: Vec<u16> = str_to_u16(&pp);
            current_loc_w.as_ptr() as LPCWSTR
        } else {
            ptr::null_mut()
        }
    };

    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let new_params = program.parameters();
    std::env::set_var("HELLO", &new_params);
    
    // Create a process in the AppContainer
    let create_process_result = unsafe {
        CreateProcessW(app_name_w.as_ptr() as LPWSTR,
                       params_w,
                       ptr::null_mut(),
                       ptr::null_mut(),
                       FALSE,
                       EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                       0 as LPVOID,
                       current_dir,
                       &mut si_ex.StartupInfo,
                       &mut pi,
        )
    };

    if create_process_result == 0 {
        return Err(SandboxError::RunAppContainerFailed(format!("Failed to create process in AppContainer! {}", get_last_error_as_string())));
    }

    // Process finished, you can check its exit code
    let mut exit_code: u32 = 0;

    unsafe {
        if pi.hProcess.is_null() {
            return Err(SandboxError::RunAppContainerFailed("The process handle is invalid!".to_string()));
        }

        let wait_result = WaitForSingleObject(pi.hProcess, INFINITE); // Wait indefinitely for the process to finish

        if wait_result == 0xFFFFFFFF { // WAIT_FAILED == 0xFFFFFFFF
            return Err(SandboxError::RunAppContainerFailed("Could not wait for the program to exit!".to_string()));
        }

        if wait_result != 0 { // Ensure we got the WAIT_OBJECT_0 (0)
            return Err(SandboxError::RunAppContainerFailed(format!("Could not wait for the program to exit! {}", get_last_error_as_string())));
        }

        let get_exit_code_result = GetExitCodeProcess(pi.hProcess, &mut exit_code);

        handleapi::CloseHandle(pi.hProcess);
        handleapi::CloseHandle(pi.hThread);

        if get_exit_code_result == 0 {
            return Err(SandboxError::RunAppContainerFailed("Failed to get exit code of the process!".to_string()));
        }

        Ok(exit_code)
    }
}

pub fn delete_appcontainer_profile(profile: &str) -> Result<(), SandboxError> {
    let profile_name: Vec<u16> = str_to_u16(profile);
    let delete_result = unsafe { DeleteAppContainerProfile(profile_name.as_ptr()) };

    if delete_result != winerror::S_OK {
        if delete_result == winerror::E_INVALIDARG {
            return Err(SandboxError::DeleteAppContainerProfileFailed(format!("Failed to delete AppContainer profile! Please ensure that the profile is correct {}", profile)));
        } else {
            return Err(SandboxError::DeleteAppContainerProfileFailed(format!("Failed to delete AppContainer profile: '{}'! {}", profile, get_last_error_as_string())));
        }
    }

    Ok(())
}

#[inline(always)]
fn str_to_u16(input: &str) -> Vec<u16> {
    OsStr::new(input).encode_wide().chain(once(0)).collect()
}

fn get_last_error_as_string() -> String {
    unsafe {
        let mut buffer: LPWSTR = ptr::null_mut();
        let error_code: DWORD = GetLastError();
        let flags = FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS;

        let lang_id = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as DWORD;

        let size = FormatMessageW(
            flags,
            ptr::null_mut(),
            error_code,
            lang_id,
            (&mut buffer) as *mut LPWSTR as LPWSTR,
            0,
            ptr::null_mut(),
        );

        let slice = std::slice::from_raw_parts(buffer, size as usize);
        let message = OsString::from_wide(slice)
            .to_string_lossy()
            .trim()
            .to_string();

        LocalFree(buffer as LPVOID);

        message
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    START.call_once(|| {
        unsafe { // Initialize COM library
            CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED);
        }
    });

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        return Err("Usage: sandboxing.exe <cat-like-program> <cat-like-program-file-argument>".into());
    }

    let exe_arg = &args[1].to_string();
    let exe_path_loc = std::path::absolute(Path::new(exe_arg))?;
    let exe_path = exe_path_loc.display().to_string();
    
    let exe_param_arg = &args[2].to_string();
    let exe_param_loc = std::path::absolute(Path::new(exe_param_arg))?;
    let host_file_path = exe_param_loc.display().to_string();

    println!("We're running {} with params {}", &exe_path, &host_file_path);
    
    let current_dir = env::current_dir().map_or_else(|_| None, |v| Some(v.display().to_string()));
    let program_loc = exe_path;
    let mut program = Program::new(program_loc.to_string(), current_dir);
    program.add_parameter(host_file_path.clone());

    let profile_name = "MyAppContainer".to_string();
    let profile_display_name = "Simple sandbox runner".to_string();
    let profile_description = "Sandboxed AppContainer on Windows".to_string();
    let create_appcontainer_profile_command = CreateAppContainerProfileCommand::new(
        profile_name.clone(),
        Some(profile_display_name),
        Some(profile_description),
    )?;

    let appcontainer_profile = create_appcontainer_profile(create_appcontainer_profile_command)?;    
    let sid_string = sid_to_string(appcontainer_profile.p_sid.raw_ptr)?;
    
    let mut acl = Dacl::from_path(&host_file_path)?;
    acl.add_entry(Ace {
        entry_type: ACCESS_ALLOWED,
        flags: 0,
        mask: GENERIC_READ,
        sid: sid_string.to_owned()
    });
    acl.apply_to_path(&host_file_path)?;

    match run_appcontainer(appcontainer_profile, program) {
        Ok(exit_code) =>{
            println!("The program exited with code: {}", exit_code);
        },
        Err(ex) => {
            eprintln!("Error occurred: {:?}", ex);
        }
    }
    
    acl.remove_entry(&sid_string, ACCESS_ALLOWED);
    acl.apply_to_path(&host_file_path)?;

    delete_appcontainer_profile(&profile_name)?;

    Ok(())
}
