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
    Write-Output "`t-Check                : Check faulty ACE in domain object DACL (default)"
    Write-Output "`t-Fix                  : Set the Inherit_Only flag in faulty ACE on domain object DACL"
    Break
}


if($help -or ($args -gt 0)) {
    Usage
}

$vulnerable = $false
$DC = Get-ADDomainController
$primaryDN = $DC.DefaultPartition
$domainObjectAcl = Get-Acl "ad:$primaryDN"
$faultyACE = $domainObjectAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteDacl' `
  -and $_.ObjectType -match '00000000-0000-0000-0000-000000000000' `
  -and $_.PropagationFlags -match 'None' `
  }
  
If($faultyACE.Count -eq 2) {
  Write-Host "The two faulty ACE were found. Exchange Windows Permissions can control the domain object."
  $vulnerable = $true
  }
Else{
  Write-Host "The two faulty ACE were not found."
  }
  
If($Fix -and !$vulnerable) {
  Write-Host "Faulty ACE were not found. Nothing to do here."
  }
  
If(!$Fix -and $vulnerable) {
  Write-Host "Relaunch with -Fix"
  }
  
If($Fix -and $vulnerable) {
  Write-Host "Setting the Inherit_Only flag in faulty ACE on domain object DACL"
  $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
  $ace0 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $faultyACE[0].IdentityReference, `
    $faultyACE[0].ActiveDirectoryRights,$faultyACE[0].AccessControlType,$faultyACE[0].ObjectType, `
	$inheritanceType,$faultyACE[0].inheritedObjectType
  $ace1 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $faultyACE[1].IdentityReference, `
    $faultyACE[1].ActiveDirectoryRights,$faultyACE[1].AccessControlType,$faultyACE[1].ObjectType, `
	$inheritanceType,$faultyACE[1].inheritedObjectType
	
  $domainObjectAcl.RemoveAccessRule($faultyACE[0])
  $domainObjectAcl.RemoveAccessRule($faultyACE[1])
  $domainObjectAcl.AddAccessRule($ace0)
  $domainObjectAcl.AddAccessRule($ace1)
  "Backing up domain object DACL in domainObjectDACL.txt"
  $domainObjectAcl.Sddl | out-file "domainObjectDACL.txt"
  Try {
    Set-Acl -aclobject $domainObjectAcl "ad:$primaryDN"
  }
  Catch {
    Write-Host "An error occurred:"
    Write-Host $_.Exception.Message
    Break
  }
  Write-Host "Done. Relaunch to check."
  
} 
