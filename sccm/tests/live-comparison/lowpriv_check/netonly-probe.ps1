# Runs INSIDE a netonly child. Proves the split identity:
#   - local token  = the launching user (domainadmin) -> netonly left it alone
#   - network id    = lowpriv                          -> outbound auth is scoped
# CreateProcessWithLogonW gives the child its own console, so results are written
# to a file the parent reads back.
$out = Join-Path $PSScriptRoot "netonly-probe.out"
"LOCAL whoami : $(whoami)" | Out-File -FilePath $out -Encoding utf8
try {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $c = New-Object System.DirectoryServices.Protocols.LdapConnection("dc.mayyhem.com")
    $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $c.SessionOptions.Sealing = $true
    $c.SessionOptions.Signing = $true
    $c.Bind()   # ambient network creds -> lowpriv under netonly
    $req  = New-Object System.DirectoryServices.Protocols.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3")
    $resp = [System.DirectoryServices.Protocols.ExtendedResponse]$c.SendRequest($req)
    $who  = [System.Text.Encoding]::UTF8.GetString($resp.ResponseValue)
    "LDAP whoami  : $who" | Out-File -FilePath $out -Encoding utf8 -Append
} catch {
    "LDAP whoami FAILED: $($_.Exception.Message)" | Out-File -FilePath $out -Encoding utf8 -Append
}
