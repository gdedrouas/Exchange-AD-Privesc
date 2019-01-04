## DNSAdmins group DACL privilege escalation

A privilege escalation is possible from the **Exchange Windows permissions** (EWP) 
and from the **Exchange Trusted Subsystem** security groups to control the DNSAdmins group and then compromise the entire prepared Active Directory domain.
This second part was described in [this work from Shay Ber](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83) in 2017


DISCLAIMER: This issue has been responsibly disclosed to MSRC in November 2018 and after a few back and forth emails, they closed the case.
Basically, they could not reproduce the issue in their testing environments. 
However, the DACL of the incriminated object on their side appears to be quite different from the DACL that I observed in several live production AD domains.
MSRC side DACL has a few *Deny* ACEs explicitely positioned for the incriminated Exchange security groups.


From there, I can only speculate that either they have an unreleased fix on their testing environments, or their path of Exchange deployment on AD is different
from what is commonly observed on live domains, which are usually upgraded and not redeployed on CU releases.


* Description of the issue

When preparing Exchange 2013/2016 installation in Shared permissions (default) or RBAC split permissions, some ACEs are positioned on the "CN=DNSAdmins,CN=Users" group for the **Exchange Windows Permissions** 
and for the **Exchange Trusted Subsystem** security groups. This probably happens during the "Setup /PrepareDomain" command of particular CU Exchange installs or during a CU upgrade.


Three ACEs give complete control on the DNSAdmins security group:

