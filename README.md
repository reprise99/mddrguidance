# MDDR Guidance
Links and guidance related to the return on mitigation report in the Microsoft Digital Defense Report - [Microsoft Digital Defense Report](aka.ms/mddr)

![image](https://github.com/reprise99/mddrguidance/assets/88635951/1d550a11-fcba-4793-b232-3e70b225f28c)

These statistics show the percentage of customers that have the issues highlighted and then seeks to map the controls to give customers direction on where investment is best placed

Below are listed various links and resources for each issue and guidance to address them

## High

### Poor user lifecycle management

#### [Microsoft Entra ID Lifecycle Management](https://learn.microsoft.com/en-us/azure/active-directory/governance/what-is-identity-lifecycle-management)
If you use Entra ID, there is a lifecycle management capability that helps you manage user onboarding, offboarding and entitlement management (ensuring users only have access to what they require)

### Lack of EDR coverage

#### [Onboard to Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/onboarding?view=o365-worldwide)
Microsoft Learn documentation showing the various ways to onboard devices

#### [Integration with Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/azure-server-integration?view=o365-worldwide)
Guidance on how MDE can integrate to Microsoft Defender for Cloud ensuring cloud workloads have the MDE sensor and are integrated fully, includes onboarding guidance

#### [MDE Blog Series](https://jeffreyappel.nl/tag/mde-series/)
A blog series from Microsoft MVP Jeffrey Appel that includes effectively onboarding devices

###  Lack of detection controls

#### [Microsoft Defender for Endpoint SecOps Guide](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/mde-sec-ops-guide?view=o365-worldwide)
A guide on how to operationalize MDE with your SecOps team. Even if you use non Microsoft EDR, there are good lessons here that you can apply to whatever tooling

###  Resource exposed to public access

#### [Internet-facing devices](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/internet-facing-devices?view=o365-worldwide)
MDE tags devices that are publicly exposed to the internet with a specifc tag that is available in the UI and in Advanced Hunting to query on. Devices that are publicly accessible are more vulnerable to exploit and should be priortized for hardening and patching

### Insufficient protections for local accounts

#### [LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
Windows LAPS is a Windows feature that manages the local administrator account on Windows devices, to reduce the risk of credential attacks like pass-the-hash, by ensuring each device has a local admin password that is unique and regularly changed

###  Missing security barrier between cloud and on-premise

#### [Protect M365](https://aka.ms/protectm365)
The protect M365 guidance seeks to protect Active Directory and Microsoft Entra ID (previously Azure Active Directory) from each other in the case of compromise. If Active Directory is compromised we want to reduce the blast radius to Microsoft Entra ID and vice versa

### Insecure Active Directory confguration

#### [Microsoft Defender for Identity - Security Posture](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment)
If you use Microsoft Defender for Identity, you can use the security posture assessments to find quick wins for securing accounts and configuration

#### [Top 10 Ways to Improve Active Directory Security Quickly](https://www.youtube.com/watch?v=Og5xfph7Gt0)
A video from Trimarc security on how to get quick security wins in Active Directory

#### [Total Identity Compromise](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/total-identity-compromise-microsoft-incident-response-lessons-on/ba-p/3753391)
A blog from the Microsoft Detection and Response Team on issues seen in Active Directory in real life compromises

#### [Certified Pre-owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
A blog covering common misconfigurations in ADCS that allow domain domination 

#### [Locksmith](https://github.com/TrimarcJake/Locksmith)
Locksmith is a lightweight tool that queries ADCS and can detect and remediate misconfigurations

### Insufficient device security controls

#### [Windows Device Security Controls](https://www.ncsc.gov.uk/collection/device-security-guidance/platform-guides/windows)
Guidance from the NCSC about hardening Windows devices

#### [MDE Device List](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machines-view-overview?view=o365-worldwide)
The inventory portal can show you the status of your devices, including whether they are enrolled in MDE, the health of the sensor and any residual device risk

###  Legacy cloud authentication is still used

#### [Block legacy authentication in Microsoft Entra Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication)
Guidance to block legacy authentication in Microsoft Entra Conditional Access. Although this was disabled for Exchange Online by Microsoft, it is recommended you block it using CA also as non Exchange Online services or custom apps may be using legacy auth

### No advanced password protection enabled

#### [Elimate weak passwords in the cloud](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad)
#### [Elimate weak passwords on-premises](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-on-premises)
Both links show how to deploy Microsoft Entra ID Password Protection, a service that lets you block poor passwords both in the cloud and on-premises. Password protection works by blocking the most common bad passwords (such as Password123) and your own custom blocklist (YourCompanyName123)

### Missing content based MFA protection mechanisms

#### [Authentication methods in Microsoft Entra ID](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)

Guidance on planning your strategy from moving away from weaker MFA methods (SMS/Phone) to modern and phishing resistant methods (FIDO2/Windows Hello for Business) 

This graphic is a great visual explainer

![Authentication Methods](https://learn.microsoft.com/en-us/azure/active-directory/authentication/media/concept-authentication-methods/authentication-methods.png)

### Insecure operating system confguration

#### [Intune Device Compliance](https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started)
Intune device compliance rules allow you to configure policies and settings your devices must adhere to in order to be granted access via Conditional Access

#### [CIS Benchmarks](https://learn.microsoft.com/en-us/compliance/regulatory/offering-cis-benchmark)
Microsoft provides guidance around aligning to CIS and other benchmarks

## Medium 

###  Legacy and unsecure protocols

#### [Detect, enable and disable SMBv1](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server)
Guidance for disabling SMB v1 and other SMB policies

#### [Killing HTML is Hard](https://syfuhs.net/killing-ntlm-is-hard)
Great blog from Steve Syfuhs from Microsoft about NTLM and the struggles to remove it

###  Missing or inconsistent update management

#### [Software updates in Intune](https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure)
Managing software updates and updates to Windows via Intune

#### [Windows Server Update Services (WSUS)](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus)
Using WSUS to update Windows

#### [Azure Update Manager](https://learn.microsoft.com/en-us/azure/update-center/overview?tabs=azure-vms)
Azure Update Manager is a unified service to help govern updates across all your machines, including Windows and Linux, across Azure, on-premises and other clouds

###  Missing cloud application management and monitoring

#### [Microsoft Defender for Cloud Apps - Connecting Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/enable-instant-visibility-protection-and-governance-actions-for-your-apps)
If you are licensed for Microsoft Defender for Cloud Apps you can connect in third party apps like ServiceNow, Atlassian, AWS for visibility into those apps. They are easy to connect and build use cases for

#### [Investigation and response in Microsoft Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate)
How to use the investigation tools and interface to investigate alerts and other suspicious activity

#### [Microsoft Entra ID SecOps Guide](https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-introduction)
A SecOps guide to Microsoft Entra ID including how to respond to compromise, what events to look for as a detection team and how to protect users and devices

###  No privileged identity management solution

#### [Microsoft Entra Privileged Identity Management Guidance](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
You can use Microsoft Entra PIM to manage privileged access to your environment by requiring additional approvals or security checks to elevate to privileged roles. This access can also be time bound

#### [Discovery and Insights for Microsoft Entra roles](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-security-wizard)
If you are just starting your PIM journey you can discover your current posture to show the spread of privileged access and use that as a foundation to reduce privilege across your environment

###  No MFA, or MFA not mandatory for privileged accounts

#### [Microsoft Entra ID - Security Defaults](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-defaults#require-administrators-to-do-multifactor-authentication)
There is an out of the box security default that will enforce MFA for privileged accounts, turn this on!

#### [Microsoft Entra ID Conditional Access Templates](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common?tabs=secure-foundation)
If you want to go beyond Security Defaults, there are lots of great CA templates available here

#### [Go Passwordless](https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key)
Your most privileged accounts should be using phishing resistance MFA, enable it here!

#### [Conditional Access Authentication Strengths](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-strengths)
Don't just enable passwordless for your most privileged accounts, enforce the use of it with authentication strengths

###  Weak email protection against common threats

#### [Microsoft Defender for Office 365 SecOps Guide](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/mdo-sec-ops-guide?view=o365-worldwide)
SecOps guide for Microsoft Defender for Office 365 and how to respond to mail based attacks. As with all these guides, even if you use non Microsoft mail security, there is valuable guidance here

#### [Configure your Microsoft 365 tenant for increased security](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/tenant-wide-setup-for-increased-security?view=o365-worldwide)
Guidance on bringing Office 365/Microsoft 365 inline with best practice

#### [Enhanced Filtering for Exchange Online](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors)
If you use third party mail filtering, you can get Exchange Online to do a secondary check by enabling Enhanced Filtering. Ain't nothing wrong with a second opinion when it comes to phishing

###  Legacy or unsupported operating systems

Sometimes there is no exciting guidance, you just need to update your old stuff!

## Lower 

###  No privilege separation

#### [Securing privileged access](https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning)
Guidance to secure privileged accounts, including seperation of on-premises admin accounts from cloud admin accounts, removal of mailboxes from admin accounts and separate admin accounts from regular day to day accounts

#### [Well Architected Framework - Admin Design](https://learn.microsoft.com/en-us/azure/well-architected/security/design-admins)
The section of the Microsoft Azure Well-Architected Framework that covers administrative account security

###  No hardened workstations used for administration

#### [Privileged access devices](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices)
Understanding why privileged access devices are important and where they fit on your privileged management journey

#### [Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
The Microsoft Enterprise Access Model guidance, this model seeks to reduce the spread of privileged credentials and paths to privileged accounts by securing tier 0 assets and users

###  Missing data classifcation and sharing restrictions

#### [Microsoft 365 Guest Settings](https://learn.microsoft.com/en-us/microsoft-365/solutions/microsoft-365-guest-settings?view=o365-worldwide)
Lists all the various locations to configure guest settings including Entra, SharePoint, OneDrive and Teams

#### [Protecting data with Microsoft Purview](https://learn.microsoft.com/en-us/purview/information-protection)
Microsoft Learn documentation on protecting data with Microsoft Purview including information labels, insider risk and data compliance

###  No vulnerability management

#### [Microsoft Defender VM](https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/defender-vulnerability-management?view=o365-worldwide)
Microsoft Defender now has vulnerabilty management capability which you can see within the M365 Defender Portal

#### [Defender VM in Azure](https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management)
You can integrate vulnerability management into Microsoft Defender for Cloud, this includes both virtual machines and vulnerability analysis for containers and other cloud native products

###  No adherence to the Least Privilege Principle 

#### [Least privileged roles by task in Microsoft Entra ID](https://learn.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task)
A list of tasks that can be completed in Microsoft Entra ID and the role that allows a user to complete that action while adhering to least privilege

#### [Least privilege in on-premises Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
Implementing least privilege administrative models in on-premises Active Directory
