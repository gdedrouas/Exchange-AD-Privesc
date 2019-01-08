#
# USE AT YOUR OWN RISK !!!
# Default -Check needs only user privileges
# Of course, -Fix needs Domain Admins privileges
# 

Param(
    [switch]$help = $false,
    [switch]$Check = $true,
    [switch]$Fix = $false
)


Function Usage([string]$errmsg = $null)
{
    if($errmsg) {
        Write-Output "Error: $errmsg"
    }

    Write-Output "Usage: $(Split-Path -Leaf $PSCommandPath) [PARAMETERS]"   
    Write-Output "Parameters:"
    Write-Output "`t-Check                : Check faulty ACE in DNSAdmins DACL (default)"
    Write-Output "`t-Fix                  : Backup and Delete faulty ACEs on DNSAdmins DACL"
    Break
}


if($help -or ($args -gt 0)) {
    Usage
}

$vulnerable = $false
$DC = Get-ADDomainController
$primaryDN = $DC.DefaultPartition
$targetGroup = "ad:\CN=DNSAdmins,CN=Users,$primaryDN"
$dNSAdminsAcl = Get-Acl $targetGroup

$controlACE_EWP1 = $dNSAdminsAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteProperty' `
  -and $_.ObjectType -match 'bf9679c0-0de6-11d0-a285-00aa003049e2' `
  -and $_.AccessControlType -match 'Allow' `
  }
$controlACE_EWP2 = $dNSAdminsAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteProperty' `
  -and $_.ObjectType -match '0296c120-40da-11d1-a9c0-0000f80367c1' `
  -and $_.AccessControlType -match 'Allow' `
  }
$controlACE_ETS = $dNSAdminsAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Trusted Subsystem' `
  -and $_.ActiveDirectoryRights -match 'WriteDacl' `
  -and $_.InheritedObjectType -match 'bf967a9c-0de6-11d0-a285-00aa003049e2' `
  -and $_.AccessControlType -match 'Allow' `
  }
If($controlACE_EWP1.Count + $controlACE_EWP2.Count + $controlACE_ETS.Count -gt 0) {
  Write-Host "The following control ACEs were found:"
  $vulnerable = $true
  $controlACE_EWP1
  $controlACE_EWP2
  $controlACE_ETS
  }
Else{
  Write-Host "NO control ACEs were found."
  break
  } 
  
$denyACE = $dNSAdminsAcl.Access | Where-Object {$_.AccessControlType -match 'Deny'}
If($denyACE.Count -gt 0) {
  Write-Host "Some Deny ACEs were found, please review manually. Exiting."
  break
  }
Else{
  Write-Host "This AD is VULNERABLE. Exchange groups can control the DNSAdmins object."
  }


  
If($Fix -and !$vulnerable) {
  Write-Host "Control ACE were not found. Nothing to do here. Exiting"
  break
  }
  
If(!$Fix -and $vulnerable) {
  Write-Host "Relaunch with -Fix to delete the faulty ACEs"
  }
  
If($Fix -and $vulnerable) {
  "#############################"
  "FIXING: REMOVING CONTROL ACEs"
  "#############################"
  "Backing up domain object DACL in dnsadmins_dacl.txt"
  $dNSAdminsAcl.Sddl | out-file "dnsadmins_dacl.txt"
  "Breaking inheritance and copy ACEs"
  $dNSAdminsAcl.SetAccessRuleProtection($True,$True)
  Try {
	Set-Acl -aclobject $dNSAdminsAcl $targetGroup -ErrorAction Stop
  }
  Catch {
    Write-Host "An error occurred:"
    Write-Host $_.Exception.Message
    Break
  }
# Get the new DACL to work from
  $dNSAdminsAcl = Get-Acl $targetGroup
  $controlACE_EWP1 = $dNSAdminsAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteProperty' `
  -and $_.ObjectType -match 'bf9679c0-0de6-11d0-a285-00aa003049e2' `
  -and $_.AccessControlType -match 'Allow' `
  }
  $controlACE_EWP2 = $dNSAdminsAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteProperty' `
  -and $_.ObjectType -match '0296c120-40da-11d1-a9c0-0000f80367c1' `
  -and $_.AccessControlType -match 'Allow' `
  }
  $controlACE_ETS = $dNSAdminsAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Trusted Subsystem' `
  -and $_.ActiveDirectoryRights -match 'WriteDacl' `
  -and $_.InheritedObjectType -match 'bf967a9c-0de6-11d0-a285-00aa003049e2' `
  -and $_.AccessControlType -match 'Allow' `
  }
  
  Write-Host "Removing the control ACEs from DNSAdmins DACL"
  $res = $dNSAdminsAcl.Access.Count
  $dNSAdminsAcl.RemoveAccessRuleSpecific($controlACE_EWP1)
  $dNSAdminsAcl.RemoveAccessRuleSpecific($controlACE_EWP2)
  $dNSAdminsAcl.RemoveAccessRuleSpecific($controlACE_ETS)  
  $res = $res - $dNSAdminsAcl.Access.Count

  Write-Host "$res control ACEs removed, committing to AD."
  
  Try {
	Set-Acl -aclobject $dNSAdminsAcl $targetGroup -ErrorAction Stop
  }
  Catch {
    Write-Host "An error occurred:"
    Write-Host $_.Exception.Message
    Break
  }
  Write-Host "Done. Relaunch script to check."
  
} 
