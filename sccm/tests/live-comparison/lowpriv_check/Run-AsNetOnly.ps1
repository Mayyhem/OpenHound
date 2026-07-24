<#
.SYNOPSIS
Launch a child process whose OUTBOUND NETWORK authentication uses alternate
credentials, while the local process token stays the current user.

.DESCRIPTION
This is the scriptable equivalent of `runas /netonly:DOMAIN\user "<cmd>"`.
`runas` reads the password from the console (unusable non-interactively), so we
call the Win32 API `CreateProcessWithLogonW` directly with the
LOGON_NETCREDENTIALS_ONLY (0x2) flag, which is exactly the "logon type 9 /
new-credentials" logon `/netonly` performs.

Why we need it: ConfigManBearPig.ps1 has no -Username/-Password parameter; it
authenticates as whatever Windows logon context it runs in. All SCCM collection
is remote (LDAP -> DC, AdminService HTTPS, SMB, RemoteRegistry, MSSQL), so
scoping only the network identity to `lowpriv` (leaving the local token alone)
is both sufficient and the closest match to how OpenHound binds with explicit
`lowpriv` credentials.

Waits for the child to exit and returns its exit code so the caller can gate on
success/failure.
#>
param(
    [Parameter(Mandatory = $true)][string]$UserName,      # e.g. lowpriv
    [Parameter(Mandatory = $true)][string]$Domain,        # e.g. MAYYHEM
    [Parameter(Mandatory = $true)][string]$Password,
    [Parameter(Mandatory = $true)][string]$CommandLine,   # full child command line
    [string]$WorkingDirectory = (Get-Location).Path,
    [int]$TimeoutSeconds = 3600
)

# P/Invoke CreateProcessWithLogonW. Defined once per session; re-adding the same
# type name throws, so guard on it.
if (-not ([System.Management.Automation.PSTypeName]'NetOnly.Launcher').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace NetOnly {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    public static class Launcher {
        // LOGON_NETCREDENTIALS_ONLY = 0x2 -> outbound network auth only (runas /netonly).
        // CREATE_UNICODE_ENVIRONMENT = 0x400 (required by the API when using default env).
        const uint LOGON_NETCREDENTIALS_ONLY = 0x00000002;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint INFINITE = 0xFFFFFFFF;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcessWithLogonW(
            string userName, string domain, string password, uint logonFlags,
            string applicationName, string commandLine, uint creationFlags,
            IntPtr environment, string currentDirectory,
            ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        public static uint Run(string user, string domain, string password,
                               string commandLine, string workingDir, int timeoutSeconds) {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;
            bool ok = CreateProcessWithLogonW(user, domain, password,
                LOGON_NETCREDENTIALS_ONLY, null, commandLine,
                CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, workingDir, ref si, out pi);
            if (!ok) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateProcessWithLogonW failed");
            }
            uint wait = timeoutSeconds <= 0 ? INFINITE : (uint)(timeoutSeconds * 1000);
            WaitForSingleObject(pi.hProcess, wait);
            uint exitCode;
            GetExitCodeProcess(pi.hProcess, out exitCode);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return exitCode;
        }
    }
}
'@
}

Write-Host "[Run-AsNetOnly] launching as $Domain\$UserName (netonly): $CommandLine"
$exit = [NetOnly.Launcher]::Run($UserName, $Domain, $Password, $CommandLine, $WorkingDirectory, $TimeoutSeconds)
Write-Host "[Run-AsNetOnly] child exit code: $exit"
exit $exit
