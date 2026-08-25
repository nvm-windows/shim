pub const preference_registry_root = "Software\\Author Software\\Preferences\\nvm";
pub const policy_registry_root = "Software\\Policies\\Author Software\\nvm";
pub const reg_value_allowed_signers = "AllowedSigners";
pub const reg_value_allowed_thumbprints = "AllowedThumbprints";
pub const reg_value_authenticode_revocation = "AuthenticodeRevocation";
pub const reg_value_air_gapped = "AirGapped";
pub const reg_value_version = "ActiveVersion";
pub const reg_value_root = "InstallRoot";
pub const reg_value_auto_use = "AutoUse";
pub const reg_value_auto_install = "AutoInstall";
pub const reg_value_auto_install_prompt = "AutoInstallPrompt";
pub const reg_value_auto_detect = "AutoDetect";
pub const reg_value_aliases = "Aliases";
pub const reg_value_log_executions = "LogExecutions";
pub const reg_value_access_token = "AccessToken";
pub const reg_value_enforce_permission_model = "EnforcePermissionModel";
pub const reg_value_freeze_v8_global_objects = "FreezeV8GlobalObjects";
pub const reg_value_disable_eval_and_string_execution = "DisableEvalAndStringExecution";
pub const reg_value_package_manager_mismatch_action = "PackageManagerMismatchAction";
pub const reg_value_npm_module_minimum_age = "NpmModuleMinimumAge";
pub const reg_value_npm_mirror = "MirrorNpm";
pub const reg_nvm_cmd_path = "Software\\Classes\\nvm\\shell\\open\\command";
pub const default_install_root = "%LOCALAPPDATA%\\Author Software\\nvm\\installs";
pub const default_auto_detect = ".nvmrc,.node-version,package.json,package-lock.json";
pub const reg_type_sz: u32 = 1;
pub const reg_type_expand_sz: u32 = 2;
pub const reg_type_dword: u32 = 4;
pub const reg_type_multi_sz: u32 = 7;
pub const reg_type_qword: u32 = 11;
pub const reg_type_binary: u32 = 3;
pub const verify_cache_subkey = "VerifyCache";
pub const verify_script_cache_subkey = "scripts";
pub const verify_dir_name = ".verify";
pub const verify_pubkey_file = "pubkey.cer";
pub const verify_pubkey_fingerprint_file = "pubkey.sha256";
pub const verify_cache_schema_version: u32 = 3;
pub const script_cache_schema_version: u32 = 1;

pub const default_allowed_signers = [_][]const u8{
    "Author Software Inc.",
    "OpenJS Foundation",
    "Node.js Foundation",
};
