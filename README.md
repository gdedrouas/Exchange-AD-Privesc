# Exchange-AD-Privesc

This repository provides a few techniques and scripts regarding the impact of Microsoft Exchange deployment on Active Directory security. This is a side project of [AD-Control-Paths](https://github.com/ANSSI-FR/AD-control-paths), an AD permissions auditing project to which I recently added some Exchange-related modules.

## TABLE OF CONTENT
0. General considerations
1. [Domain object DACL privilege escalation](DomainObject/DomainObject.md)
2. [DNSAdmins group DACL privilege escalation](DNSAdmins/DNSAdmins.md)
3. [Public-Information property set includes SPN, allows kerberoasting](Write-Public-Information/Write-Public-Information.md)


## General considerations

For pentesters looking to take control of an AD domain, Exchange is a valid intermediary target. The servers are much less secured than domain controllers by default and the control groups are distinct in the usual permissions models, which provides numerous alternative targets.
They are also more difficult to migrate and business critical, so organizations often adopt a slower migration process for Exchange than for AD and do not specifically harden the servers.

Exchange deployment on an Active Directory domain is an interesting case. Many attributes and classes are added to the schema, security groups are created and DACL on some AD objects are heavily modified. 

Basically, you can select among 3 permissions models:

* RBAC Split (recommended and most commonly deployed)
* Shared permissions (default)
* AD Split

Particularly, DACLs for RBAC Split and Shared models are enumerated here: https://technet.microsoft.com/en-us/library/ee681663(v=exchg.150).aspx .


High value targets:

* **Exchange Trusted Subsystem** and **Exchange Windows Permissions** groups, which are trustees for many ACE added during deployment on AD objects.
* Exchange servers: they are members of **Exchange Trusted Subsystem** and **Exchange Windows Permissions** groups. They can be compromised using many more techniques than domain controllers: local administrators domain accounts, Kerberos delegation, SMB relay, RODC replication, etc. The usual stuff.
* Organization admins: they are part of the local administrators group on Exchange servers. They also have full control on the OU containing the Exchange security groups. They can launch service/psexec/runas/... under computer identity/NetworkService/LocalSystem to control **Exchange Trusted Subsystem** and **Exchange Windows Permissions** SIDs.

