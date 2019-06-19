

## Write Public-Information ACE leads to Kerberoasting from Exchange security groups

An attack vector exists from the **Exchange Enterprise Servers** 
and from the **Exchange Trusted Subsystem** security groups to obtain the encrypted TGS of any domain account through SPN manipulation then a "kerberoast"-style attack. The TGS can potentially be cracked to recover the plaintext passwords.
This second part was described in [this work from Tim Medin](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf) in 2014.

This issue was discovered and responsibly disclosed to MSRC by [aurel26](https://github.com/aurel26/). It has been fixed in the [June 2019 Quarterly Exchange update](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-June-2019-Quarterly-Exchange-Updates/ba-p/698398).


* Description of the issue

In up-to-date deployments of Exchange 2016 in Shared permissions (default) or RBAC model, ACEs allowing to write SPNs through Public-Information property set are positioned on the Domain Object and on the AdminSDHolder object for the **Exchange Trusted Subsystem** security group 
and for the **Exchange Enterprise Servers** security groups. [Those ACEs are partially documented](https://docs.microsoft.com/en-us/exchange/exchange-2013-deployment-permissions-reference-exchange-2013-help).

The Public-Information property set is intended for non-sensitive attributes such as department, phone number etc. However, it also contains Service-Principal-Name which is a Kerberos-related attribute. ACEs allowing to write this property also allow to add SPNs to the object. Accounts with SPNs can be kerberoasted, which is not a problem in itself when their passwords have high entropy, such as machine accounts or managed service accounts. On the other hand, it can easily lead to cracking and compromise when a human sets a relatively "weak" password.


All in all, it is a design problem. The Public-Information property set should only contain non-sensitive attributes and especially not security data like Service-Principal-Name. 


```
(OA;CI;WP;e48d0154-bcf8-11d1-8702-00c04fb96050;;<SID of EES>)
(OA;CI;WP;e48d0154-bcf8-11d1-8702-00c04fb96050;;<SID of ETS>)
```

Which translate into:

| Account | ACE type | Inheritance | Permissions | On property/ Applies to | Comments |
| ------- | -------- | ----------- | ----------- | ----------------------- | -------- |
| Exchange Enterprise Servers | Allow ACE | All | WriteProp | Public-Information / | |
| Exchange Trusted Subsystem | Allow ACE | All | WriteProp | Public-Information/ | |


* Technical consequence

Any member of Exchange Trusted Subsystem or Exchange Enterprise Servers can add Service Principal Names to any account in the domain. 

* Security Consequence

Setting SPNs on unexpected privileged user accounts allows TGS requesting, cracking and potential plaintext password recovery.

* Proof of concept

1) From an Organization Management member account, add yourself to Exchange Trusted Subsystem.
This is possible by default and normal.

```
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$user = Get-ADUser -Identity $id.User
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members $user
```

2) LOG OUT AND RELOG THE USERS SESSION to update groups in token

3) Add a Service Principal Name to a victim target account.
This is the problem, it should not be possible

```
setspn -s testspn/computer.domain.local <targetaccount>
```

4) "Kerberoast" the target account (Invoke-Kerberoast...)
This is the jargon for requesting an encrypted TGS for the target account, as if it were a service account.
If your AD is not specifically hardened, this TGS will be encrypted with RC4 (type 23), which is a lot faster to crack than AES-encrypted tickets.

5) Use your favorite password cracking tool (Hashcat...) to try and recover the plaintext password of the target account.

* Microsoft has published a fix for this issue

It involves running setup.exe /PrepareAD to deny or remove those ACEs. See https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-June-2019-Quarterly-Exchange-Updates/ba-p/698398


* Workaround fixes (now unnecessary, see previous part)

You could just do nothing and rely on a *strong* password policy on your sensitive accounts to prevent them from being cracked. However, real-life situations often ask for defense in depth.

A crude but safe way of mitigating this problem is denying Everyone from writing the SPN of your sensitive accounts, beginning with the AdminSDHolder DACL.

It can be done manually with LDP: bind as a Domain Admin account with the usual precautions, as you will change the AdminSDHolder DACL.

Backup the DACL: 

```
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=...").Sddl | Out-File "adminsdholder_dacl.txt"
```

Locate the "CN=AdminSDHolder,CN=System,DC=..." object, right-click "Security Descriptor", untick "Text Dump". Add... Select Trustee: "Everyone", Type: "Deny", Access Mask: "Write Property", ACE Flags: "Inherit", Object Type:  "servicePrincipalName - attribute" (will be displayed differently, it shares its GUID with the SPN validated right), Inherited Object Type: "None".

If you need to revert this change, you can simply delete this new ACE.


Another way of solving this issue is modifying the schema (not recommended). If you still feel comfortable doing it (Lab work...), you have to clean the Rights-Guid Attribute in the Service-Principal-Name schema object. Its default value is e48d0154-bcf8-11d1-8702-00c04fb96050 (Public-Information property set), just remove that. 



