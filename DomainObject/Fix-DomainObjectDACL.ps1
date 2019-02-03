#
# USE AT YOUR OWN RISK !!!
# -Check (default) needs only user privileges
# -Fix and -Restore need Domain Admins privileges
#

Param(
    [switch]$help = $false,
    [switch]$Check = $true,
    [switch]$Fix = $false,
    [switch]$Restore = $false
)


Function Usage([string]$errmsg = $null)
{
    if($errmsg) {
        Write-Output "Error: $errmsg"
    }

    Write-Output "Usage: $(Split-Path -Leaf $PSCommandPath) [PARAMETERS]"   
    Write-Output "Parameters:"
    Write-Output "`t-Check                : Check faulty ACE in domain object DACL (default)"
    Write-Output "`t-Fix                  : Set the InheritOnly flag in faulty ACEs on domain object DACL"
    Write-Output "`t-Restore              : Restore the 2 modified ACEs to their original state, which is VULNERABLE"
    Break
}


if($help -or ($args -gt 0)) {
    Usage
}
$dateString = $(((get-date).ToUniversalTime()).ToString("yyyyMMddThhmmssZ"))
$vulnerable = $false
$fixed = $false
$DC = Get-ADDomainController
$primaryDN = $DC.DefaultPartition
$domainObjectAcl = Get-Acl "ad:$primaryDN"

$faultyACE = $domainObjectAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteDacl' `
  -and $_.ObjectType -match '00000000-0000-0000-0000-000000000000' `
  -and $_.PropagationFlags -match 'None' `
  }  
If($faultyACE.Count -eq 2) {
  Write-Host "The two faulty ACEs were found. Exchange Windows Permissions can control the domain object."
  $vulnerable = $true
  }
  
$fixedACE = $domainObjectAcl.Access | Where-Object {$_.IdentityReference -match '\\Exchange Windows Permissions' `
  -and $_.ActiveDirectoryRights -match 'WriteDacl' `
  -and $_.ObjectType -match '00000000-0000-0000-0000-000000000000' `
  -and $_.PropagationFlags -match 'InheritOnly' `
  }
If($fixedACE.Count -eq 2) {
  Write-Host "The two ACEs were found to have been fixed in the past."
  $fixed = $true
  }  
  

If($Fix -and !$vulnerable) {
  Write-Host "Faulty ACEs were not found. Nothing to do here."
  }
  
If(!$Fix -and $vulnerable) {
  Write-Host "Relaunch with -Fix"
  }
If($Restore -and !$fixed) {
  Write-Host "Fixed ACEs were not found. Nothing to do here."
  }
  
If(!$Restore -and $fixed) {
  Write-Host "You can restore the original ACEs with -Restore"
  }
  
  
# Fixing the InheritOnly flag
If($Fix -and $vulnerable) {
  "Backing up domain object DACL in domainObjectDACL_"+"$dateString"+"_Fix.txt"
  $domainObjectAcl.Sddl | out-file $("domainObjectDACL_"+"$dateString"+"_Fix.txt")

  Write-Host "Setting the InheritOnly flag on the two faulty ACEs of the domain object DACL"
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

  Try {
    Set-Acl -aclobject $domainObjectAcl "ad:$primaryDN" -ErrorAction Stop
  }
  Catch {
    Write-Host "An error occurred:"
    Write-Host $_.Exception.Message
    Break
  }
  Write-Host "Done. Relaunch to check."
  
} 

# Restoring the two ACEs, MAKING AD VULNERABLE!
If($Restore -and $fixed) {
  "Backing up domain object DACL in domainObjectDACL_"+"$dateString"+"_Restore.txt"
  $domainObjectAcl.Sddl | out-file $("domainObjectDACL_"+"$dateString"+"_Restore.txt")

  Write-Host "Resetting the InheritOnly flag, restoring the previously fixed ACEs to their original state."
  Write-Host "This operation makes AD vulnerable !!!"
  $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
  $ace0 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $fixedACE[0].IdentityReference, `
    $fixedACE[0].ActiveDirectoryRights,$fixedACE[0].AccessControlType,$fixedACE[0].ObjectType, `
	$inheritanceType,$fixedACE[0].inheritedObjectType
  $ace1 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $fixedACE[1].IdentityReference, `
    $fixedACE[1].ActiveDirectoryRights,$fixedACE[1].AccessControlType,$fixedACE[1].ObjectType, `
	$inheritanceType,$fixedACE[1].inheritedObjectType
	
  $domainObjectAcl.RemoveAccessRule($fixedACE[0])
  $domainObjectAcl.RemoveAccessRule($fixedACE[1])
  $domainObjectAcl.AddAccessRule($ace0)
  $domainObjectAcl.AddAccessRule($ace1)

  Try {
    Set-Acl -aclobject $domainObjectAcl "ad:$primaryDN" -ErrorAction Stop
  }
  Catch {
    Write-Host "An error occurred:"
    Write-Host $_.Exception.Message
    Break
  }
  Write-Host "Done. Relaunch to check."
  
} 