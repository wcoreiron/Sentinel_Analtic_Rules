# Sentinel_Analtic_Rules

#Test_Emotet Related IP addresses
Description
While Emotet historically was a banking malware organized in a botnet, nowadays Emotet is mostly seen as infrastructure as a service for content delivery. 
For example, since mid 2018 it is used by Trickbot for installs, which may also lead to ransomware attacks using Ryuk,
a combination observed several times against high-profile targets. It is always stealing information from victims
but what the criminal gang behind it did, was to open up another business channel by selling their infrastructure delivering additional malicious software. 
From malware analysts it has been classified into epochs depending on command and control, payloads, and delivery solutions which change over time.
Emotet had been taken down by authorities in January 2021, though it appears to have sprung back to life in November 2021.

Tactics and techniques
Command and Control (0)
Execution (0)
let IPList = externaldata(IPAddress: string)[@"https://raw.githubusercontent.com/wcoreironrrtx/Emotet_IP_Banlist/main/README.md"] with (format="csv", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
//Network logs
let CSlogSourceIP = CommonSecurityLog
    | summarize by IPAddress = SourceIP, Type;
let CSlogDestIP = CommonSecurityLog
    | summarize by IPAddress = DestinationIP, Type;
let CSlogMsgIP = CommonSecurityLog
    | extend MessageIP = extract(IPRegex, 0, Message)
    | summarize by IPAddress = MessageIP, Type;
let DnsIP = DnsEvents
    | summarize by IPAddress = IPAddresses, Type;
// If you have enabled the imDNS and/or imNetworkSession normalization in your workspace, you can uncomment one or both below.  Reference - https://docs.microsoft.com/azure/sentinel/normalization
//let imDnsIP = imDns (response_has_any_prefix=IPList) | summarize by IPAddress = ResponseName, Type;
//let imNetSessIP = imNetworkSession (dstipaddr_has_any_prefix=IPList) | summarize by IPAddress = DstIpAddr, Type;
//Cloud service logs
let officeIP = OfficeActivity
    | summarize by IPAddress = ClientIP, Type;
let signinIP = SigninLogs
    | summarize by IPAddress, Type;
let nonintSigninIP = AADNonInteractiveUserSignInLogs
    | summarize by IPAddress, Type;
let azureActIP = AzureActivity
    | summarize by IPAddress = CallerIpAddress, Type;
let awsCtIP = AWSCloudTrail
    | summarize by IPAddress = SourceIpAddress, Type;
//Device logs
let vmConnSourceIP = VMConnection
    | summarize by IPAddress = SourceIp, Type;
let vmConnDestIP = VMConnection
    | summarize by IPAddress = DestinationIp, Type;
let iisLogIP = W3CIISLog
    | summarize by IPAddress = cIP, Type;
let devNetIP = DeviceNetworkEvents
    | summarize by IPAddress = RemoteIP, Type;
//need to parse to get IP
let azureDiagIP = AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule") 
    | where msg_s has_any (IPList)
    | parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
    | summarize by IPAddress = DestinationHost, Type;
let sysEvtIP = Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | where EventData has_any (IPList)
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"])
    | where SourceIP in (IPList) or DestinationIP in (IPList)
    | extend IPAddress = iff(SourceIP in (IPList), SourceIP, DestinationIP)
    | summarize by IPAddress, Type;
// If you have enabled the imDNS and/or imNetworkSession normalization in your workdspace, you can uncomment below and include. Reference - https://docs.microsoft.com/azure/sentinel/normalization
//let ipsort = union isfuzzy=true CSlogDestIP, CSlogMsgIP, CSlogSourceIP, DnsIP, officeIP, signinIP, nonintSigninIP, azureActIP, awsCtIP, vmConnDestIP, vmConnSourceIP, azureDiagIP, sysEvtIP, imDnsIP, imNetSessIP
// If you uncomment above, then comment out the line below
let ipsort = union isfuzzy=true
        CSlogDestIP,
        CSlogMsgIP,
        CSlogSourceIP,
        DnsIP,
        officeIP,
        signinIP,
        nonintSigninIP,
        azureActIP,
        awsCtIP,
        vmConnDestIP,
        vmConnSourceIP,
        azureDiagIP,
        sysEvtIP
    | summarize by IPAddress
    | where isnotempty(IPAddress)
    | where not(ipv4_is_private(IPAddress)) and IPAddress !in ('0.0.0.0', '127.0.0.1');
let ipMatch = ipsort
    | where IPAddress in (IPList);
(union isfuzzy=true
    (CommonSecurityLog
    | where SourceIP in (ipMatch) or DestinationIP in (ipMatch) or Message has_any (ipMatch)
    | project TimeGenerated, SourceIP, DestinationIP, Message, SourceUserID, RequestURL, Type
    | extend MessageIP = extract(IPRegex, 0, Message)
    | extend IPMatch = case(SourceIP in (ipMatch), "SourceIP", DestinationIP in (ipMatch), "DestinationIP", MessageIP in (ipMatch), "Message", "No Match")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, IPMatch == "Message", MessageIP, "No Match")
    ),
    (OfficeActivity
    | where ClientIP in (ipMatch)
    | project TimeGenerated, UserAgent, Operation, RecordType, UserId, ClientIP, Type
    | extend SourceIPAddress = ClientIP, Account = UserId
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = SourceIPAddress,
        AccountCustomEntity = Account
    ),
    (DnsEvents
    | where IPAddresses has_any (ipMatch)
    | project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
    | extend DestinationIPAddress = IPAddresses, Host = Computer
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = DestinationIPAddress,
        HostCustomEntity = Host
    ),
    (VMConnection
    | where SourceIp in (ipMatch) or DestinationIp in (ipMatch)
    | project TimeGenerated, Computer, SourceIp, DestinationIp, Type
    | extend IPMatch = case(SourceIp in (ipMatch), "SourceIP", DestinationIp in (ipMatch), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "None"),
        Host = Computer
    ),
    (Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | where EventData has_any (ipMatch)
    | project TimeGenerated, EventData, UserName, Computer, Type
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"])
    | where SourceIP in (ipMatch) or DestinationIP in (ipMatch)
    | extend IPMatch = case(SourceIP in (ipMatch), "SourceIP", DestinationIP in (ipMatch), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserName,
        HostCustomEntity = Computer,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
    ),
    (SigninLogs
    | where IPAddress in (ipMatch)
    | project TimeGenerated, UserPrincipalName, IPAddress, Type
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress
    ),
    (AADNonInteractiveUserSignInLogs
    | where IPAddress in (ipMatch)
    | project TimeGenerated, UserPrincipalName, IPAddress, Type
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress
    ),
    (W3CIISLog
    | where cIP in (ipMatch)
    | project TimeGenerated, Computer, cIP, csUserName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = cIP,
        HostCustomEntity = Computer,
        AccountCustomEntity = csUserName
    ),
    (AzureActivity
    | where CallerIpAddress in (ipMatch)
    | project TimeGenerated, CallerIpAddress, Caller, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = CallerIpAddress,
        AccountCustomEntity = Caller
    ),
    (
    AWSCloudTrail
    | where SourceIpAddress in (ipMatch)
    | project TimeGenerated, SourceIpAddress, UserIdentityUserName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = SourceIpAddress,
        AccountCustomEntity = UserIdentityUserName
    ), 
    ( 
    DeviceNetworkEvents
    | where RemoteIP in (ipMatch)
    | project TimeGenerated, RemoteIP, DeviceName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = RemoteIP,
        HostCustomEntity = DeviceName
    ),
    (
    AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule")
    | where msg_s has_any (ipMatch)
    | project TimeGenerated, msg_s, Type
    | parse msg_s with Protocol 'request from ' SourceIP ':' SourcePort 'to ' DestinationIP ':' DestinationPort '. Action:' Action
    | where DestinationIP has_any (ipMatch)
    | extend timestamp = TimeGenerated, IPCustomEntity = DestinationIP
    )
// If you have enabled the imDNS and/or imNetworkSession normalization in your workdspace, you can uncomment below and include. Reference - https://docs.microsoft.com/azure/sentinel/normalization
//,
//(imDns (response_has_any_prefix=IPList)
//| project TimeGenerated, ResponseName, SrcIpAddr, Type
//| extend DestinationIPAddress = ResponseName,  Host = SrcIpAddr
//| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host
//),
//(imNetworkSession (dstipaddr_has_any_prefix=IPList)
//| project TimeGenerated, DstIpAddr, SrcIpAddr, Type
//| extend timestamp = TimeGenerated, IPCustomEntity = DstIpAddr, HostCustomEntity = SrcIpAddr
//)
)

################################################################
#Test-Clearing of forensic evidence from event logs using wevtutil
Description
This query checks for attempts to clear at least 10 log entries from event logs using wevtutil.

// # Clearing of forensic evidence from event logs using wevtutil
// 
// This query checks for attempts to clear at least 10 log entries from event logs using wevtutil.
// 
// This query was updated on 2021-05-19 from https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/tree/master/Ransomware/Clearing%20of%20forensic%20evidence%20from%20event%20logs%20using%20wevtutil.md
// Look for use of wevtutil to clear multiple logs
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "WEVTUTIL" and ProcessCommandLine has "CL"
| summarize
    LogClearCount = dcount(ProcessCommandLine),
    ClearedLogList = make_set(ProcessCommandLine)
    by DeviceId, bin(Timestamp, 5m)
| where LogClearCount > 10


################################################################
#Test-CVE-2021-44228 - Apache Log4j Remote Code Execution Vulnerability
Description
Identifies a match across various data feeds for IP IOCs related to the Log4j vulnerability exploit aka Log4Shell described in CVE-2021-44228.
References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228'

Tactics and techniques
Command and Control (0)

let IPList = externaldata(IPAddress: string)[@"https://raw.githubusercontent.com/wcoreironrrtx/log4j_scanning_IPs.txt/main/README.md"] with (format="csv", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
//Network logs
let CSlogSourceIP = CommonSecurityLog
    | summarize by IPAddress = SourceIP, Type;
let CSlogDestIP = CommonSecurityLog
    | summarize by IPAddress = DestinationIP, Type;
let CSlogMsgIP = CommonSecurityLog
    | extend MessageIP = extract(IPRegex, 0, Message)
    | summarize by IPAddress = MessageIP, Type;
let DnsIP = DnsEvents
    | summarize by IPAddress = IPAddresses, Type;
// If you have enabled the imDNS and/or imNetworkSession normalization in your workspace, you can uncomment one or both below.  Reference - https://docs.microsoft.com/azure/sentinel/normalization
//let imDnsIP = imDns (response_has_any_prefix=IPList) | summarize by IPAddress = ResponseName, Type;
//let imNetSessIP = imNetworkSession (dstipaddr_has_any_prefix=IPList) | summarize by IPAddress = DstIpAddr, Type;
//Cloud service logs
let officeIP = OfficeActivity
    | summarize by IPAddress = ClientIP, Type;
let signinIP = SigninLogs
    | summarize by IPAddress, Type;
let nonintSigninIP = AADNonInteractiveUserSignInLogs
    | summarize by IPAddress, Type;
let azureActIP = AzureActivity
    | summarize by IPAddress = CallerIpAddress, Type;
let awsCtIP = AWSCloudTrail
    | summarize by IPAddress = SourceIpAddress, Type;
//Device logs
let vmConnSourceIP = VMConnection
    | summarize by IPAddress = SourceIp, Type;
let vmConnDestIP = VMConnection
    | summarize by IPAddress = DestinationIp, Type;
let iisLogIP = W3CIISLog
    | summarize by IPAddress = cIP, Type;
let devNetIP = DeviceNetworkEvents
    | summarize by IPAddress = RemoteIP, Type;
//need to parse to get IP
let azureDiagIP = AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule") 
    | where msg_s has_any (IPList)
    | parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
    | summarize by IPAddress = DestinationHost, Type;
let sysEvtIP = Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | where EventData has_any (IPList)
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"])
    | where SourceIP in (IPList) or DestinationIP in (IPList)
    | extend IPAddress = iff(SourceIP in (IPList), SourceIP, DestinationIP)
    | summarize by IPAddress, Type;
// If you have enabled the imDNS and/or imNetworkSession normalization in your workdspace, you can uncomment below and include. Reference - https://docs.microsoft.com/azure/sentinel/normalization
//let ipsort = union isfuzzy=true CSlogDestIP, CSlogMsgIP, CSlogSourceIP, DnsIP, officeIP, signinIP, nonintSigninIP, azureActIP, awsCtIP, vmConnDestIP, vmConnSourceIP, azureDiagIP, sysEvtIP, imDnsIP, imNetSessIP
// If you uncomment above, then comment out the line below
let ipsort = union isfuzzy=true
        CSlogDestIP,
        CSlogMsgIP,
        CSlogSourceIP,
        DnsIP,
        officeIP,
        signinIP,
        nonintSigninIP,
        azureActIP,
        awsCtIP,
        vmConnDestIP,
        vmConnSourceIP,
        azureDiagIP,
        sysEvtIP
    | summarize by IPAddress
    | where isnotempty(IPAddress)
    | where not(ipv4_is_private(IPAddress)) and IPAddress !in ('0.0.0.0', '127.0.0.1');
let ipMatch = ipsort
    | where IPAddress in (IPList);
(union isfuzzy=true
    (CommonSecurityLog
    | where SourceIP in (ipMatch) or DestinationIP in (ipMatch) or Message has_any (ipMatch)
    | project TimeGenerated, SourceIP, DestinationIP, Message, SourceUserID, RequestURL, Type
    | extend MessageIP = extract(IPRegex, 0, Message)
    | extend IPMatch = case(SourceIP in (ipMatch), "SourceIP", DestinationIP in (ipMatch), "DestinationIP", MessageIP in (ipMatch), "Message", "No Match")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, IPMatch == "Message", MessageIP, "No Match")
    ),
    (OfficeActivity
    | where ClientIP in (ipMatch)
    | project TimeGenerated, UserAgent, Operation, RecordType, UserId, ClientIP, Type
    | extend SourceIPAddress = ClientIP, Account = UserId
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = SourceIPAddress,
        AccountCustomEntity = Account
    ),
    (DnsEvents
    | where IPAddresses has_any (ipMatch)
    | project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
    | extend DestinationIPAddress = IPAddresses, Host = Computer
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = DestinationIPAddress,
        HostCustomEntity = Host
    ),
    (VMConnection
    | where SourceIp in (ipMatch) or DestinationIp in (ipMatch)
    | project TimeGenerated, Computer, SourceIp, DestinationIp, Type
    | extend IPMatch = case(SourceIp in (ipMatch), "SourceIP", DestinationIp in (ipMatch), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "None"),
        Host = Computer
    ),
    (Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | where EventData has_any (ipMatch)
    | project TimeGenerated, EventData, UserName, Computer, Type
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"])
    | where SourceIP in (ipMatch) or DestinationIP in (ipMatch)
    | extend IPMatch = case(SourceIP in (ipMatch), "SourceIP", DestinationIP in (ipMatch), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserName,
        HostCustomEntity = Computer,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
    ),
    (SigninLogs
    | where IPAddress in (ipMatch)
    | project TimeGenerated, UserPrincipalName, IPAddress, Type
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress
    ),
    (AADNonInteractiveUserSignInLogs
    | where IPAddress in (ipMatch)
    | project TimeGenerated, UserPrincipalName, IPAddress, Type
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress
    ),
    (W3CIISLog
    | where cIP in (ipMatch)
    | project TimeGenerated, Computer, cIP, csUserName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = cIP,
        HostCustomEntity = Computer,
        AccountCustomEntity = csUserName
    ),
    (AzureActivity
    | where CallerIpAddress in (ipMatch)
    | project TimeGenerated, CallerIpAddress, Caller, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = CallerIpAddress,
        AccountCustomEntity = Caller
    ),
    (
    AWSCloudTrail
    | where SourceIpAddress in (ipMatch)
    | project TimeGenerated, SourceIpAddress, UserIdentityUserName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = SourceIpAddress,
        AccountCustomEntity = UserIdentityUserName
    ), 
    ( 
    DeviceNetworkEvents
    | where RemoteIP in (ipMatch)
    | where ActionType == "InboundConnectionAccepted"
    | project TimeGenerated, RemoteIP, DeviceName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = RemoteIP,
        HostCustomEntity = DeviceName
    ),
    (
    AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule")
    | where msg_s has_any (ipMatch)
    | project TimeGenerated, msg_s, Type
    | parse msg_s with Protocol 'request from ' SourceIP ':' SourcePort 'to ' DestinationIP ':' DestinationPort '. Action:' Action
    | where DestinationIP has_any (ipMatch)
    | extend timestamp = TimeGenerated, IPCustomEntity = DestinationIP
    )
// If you have enabled the imDNS and/or imNetworkSession normalization in your workdspace, you can uncomment below and include. Reference - https://docs.microsoft.com/azure/sentinel/normalization
//,
//(imDns (response_has_any_prefix=IPList)
//| project TimeGenerated, ResponseName, SrcIpAddr, Type
//| extend DestinationIPAddress = ResponseName,  Host = SrcIpAddr
//| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host
//),
//(imNetworkSession (dstipaddr_has_any_prefix=IPList)
//| project TimeGenerated, DstIpAddr, SrcIpAddr, Type
//| extend timestamp = TimeGenerated, IPCustomEntity = DstIpAddr, HostCustomEntity = SrcIpAddr
//)
)


################################################################
#Test-Exploitation attempt against SpringShell (CVE-2022-22965)

Description
At least two vulnerabilities in the Spring Framework for Java have been publicly disclosed and can allow an attacker to remotely execute arbitrary code on 
an affected device. Microsoft is aware of these vulnerabilities and is actively investigating.

The Spring Framework is the most widely used lightweight open source framework for Java. In versions JDK .09 and later of the Spring Framework,
a remote attacker can obtain an AccessLogValve object through the framework’s parameter binding feature, and use malicious field values to trigger 
the pipeline mechanism and write to a file in an arbitrary path, if certain conditions are met.

One of the vulnerabilities exists in the Spring Cloud Function and has been assigned CVE-2022-22963. The vulnerability in Spring Core—known as 
SpringShell (CVE-2022-22965)—can be exploited when an attacker sends a specially crafted query to a web server running the Spring Core framework.

Impacted systems have the following traits:

Running JDK 9.0 or later Apache Tomcat as the Servlet container Packaged as a WAR (as opposed to the standard Spring Boot jar) Dependent on 
spring-webmvc or spring-webflux

Tactics and techniques
Execution (1)
T1203 - Exploitation for Client Execution

// Get any devices with SpringShell related Alert Activity
let DevicesSpringShellAlerts = AlertInfo
    | where Title in~('Suspicious script launched',
        'Exploitation attempt against SpringShell (CVE-2022-22965)',
        'Suspicious process executed by a network service',
        'Possible target of SpringShell exploitation (CVE-2022-22965)',
        'Possible target of SpringShell exploitation',
        'Possible SpringShell exploitation',
        'Network connection seen in CVE-2022-22965 exploitation',
        'SpringShell exploitation detected',
        'Possible exploitation of CVE-2022-22965',
        'Possible target of SpringShell vulnerability (CVE-2022-22965) scanning',
        'Possible source of SpringShell exploitation')
    // Join in evidence information
    | join AlertEvidence on AlertId
    | where DeviceId != ""
    | summarize by DeviceId, Title;
// Get additional alert activity for each device
AlertEvidence
| where DeviceId in(DevicesSpringShellAlerts)
// Add additional info
| join kind=leftouter AlertInfo on AlertId
| summarize DeviceAlerts = make_set(Title), AlertIDs = make_set(AlertId) by DeviceId, bin(Timestamp, 10d)

################################################################
#Test-Malware related to Daxin activity
Description
Daxin: Stealthy Backdoor Designed for Attacks Against Hardened Networks As described in more detail below, 
Daxin comes in the form of a Windows kernel driver, a relatively rare format for malware nowadays. 
It implements advanced communications functionality, which both provides a high degree of stealth and permits the attackers to communicate with
infected computers on highly secured networks, where direct internet connectivity is not available. These features are reminiscent of Regin,
an advanced espionage tool discovered by Symantec in 2014 that others have linked to Western intelligence services.

Tactics and techniques
Exfiltration (0)

let SHA256Hash = "1174fd03271f80f5e2a6435c72bdd0272a6e3a37049f6190abf125b216a83471"
    "81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1"
    "06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4"
    "0f82947b2429063734c46c34fb03b4fa31050e49c27af15283d335ea22fe0555"
    "3e7724cb963ad5872af9cfb93d01abf7cd9b07f47773360ad0501592848992f4"
    "447c3c5ac9679be0a85b3df46ec5ee924f4fbd8d53093125fd21de0bff1d2aad" 
    "49c827cf48efb122a9d6fd87b426482b7496ccd4a2dbca31ebbf6b2b80c98530"
    "5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae"
    "5c1585b1a1c956c7755429544f3596515dfdf928373620c51b0606a520c6245a"
    "6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f" 
    "7867ba973234b99875a9f5138a074798b8d5c65290e365e09981cceb06385c54"
    "7a08d1417ca056da3a656f0b7c9cf6cd863f9b1005996d083a0fc38d292b52e9"
    "8d9a2363b757d3f127b9c6ed8f7b8b018e652369bc070aa3500b3a978feaa6ce"
    "b0eb4d999e4e0e7c2e33ff081e847c87b49940eb24a9e0794c6aa9516832c427"
    "b9dad0131c51e2645e761b74a71ebad2bf175645fa9f42a4ab0e6921b83306e3" 
    "cf00e7cc04af3f7c95f2b35a6f3432bef990238e1fa6f312faf64a50d495630a"
    "e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e" 
    "ea3d773438c04274545d26cc19a33f9f1dbbff2a518e4302addc1279f9950cef"
    "08dc602721c17d58a4bc0c74f64a7920086f776965e7866f68d1676eb5e7951f" 
    "53d23faf8da5791578c2f5e236e79969289a7bba04eee2db25f9791b33209631" 
    "7a7e8df7173387aec593e4fe2b45520ea3156c5f810d2bb1b2784efd1c922376" 
    "8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e" 
    "96bf3ee7c6673b69c6aa173bb44e21fa636b1c2c73f4356a7599c121284a51cc" 
    "9c2f3e9811f7d0c7463eaa1ee6f39c23f902f3797b80891590b43bbe0fdf0e51"
    "c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c" 
    "e6a7b0bc01a627a7d0ffb07faddb3a4dd96b6f5208ac26107bdaeb3ab1ec8217";
(union isfuzzy=true
    (CommonSecurityLog 
    | parse Message with * '(' DNSName ')' * 
    | where isnotempty(FileHash)
    | where FileHash in (SHA256Hash) 
    | extend Account = SourceUserID, Computer = DeviceName, IPAddress = SourceIP
    ),
    (Event
    //This query uses sysmon data depending on table name used this may need updataing
    | where Source == "Microsoft-Windows-Sysmon"
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend Hashes = EventDetail.[16].["#text"]
    | parse Hashes with * 'SHA256=' SHA265 ',' * 
    | where isnotempty(Hashes)
    | where Hashes in (SHA256Hash) 
    | extend Account = UserName
    )
)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = Account,
    HostCustomEntity = Computer,
    IPCustomEntity = IPAddress
    
################################################################
#Test-Multiple signs of ransomware activity
Description
// Looks for both relatively concrete and subtle signs of ransomware activity 
// Weighs the presence of these signs 
// Identifies devices with a higher chance of being targets of ransomware 
// When run, this consolidated query returns a list of devices that have exhibited multiple signs of attack. 
The count of each type of ransomware activity is also shown.

Tactics and techniques
Discovery (0)
Initial Access (0)
Lateral Movement (0)
Privilege Escalation (0)
// # Check for multiple signs of ransomware activity
// 
// Instead of running several queries separately, you can also use a comprehensive query that checks for multiple signs of ransomware activity to identify affected devices. The following consolidated query:
// 
// Looks for both relatively concrete and subtle signs of ransomware activity
// Weighs the presence of these signs
// Identifies devices with a higher chance of being targets of ransomware
// When run, this consolidated query returns a list of devices that have exhibited multiple signs of attack. The count of each type of ransomware activity is also shown.
// 
// This query was updated on 2021-05-19 from https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/tree/master/Ransomware/Check%20for%20multiple%20signs%20of%20ransomware%20activity.md
// Find attempts to stop processes using taskkill.exe
let taskKill = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName =~ "taskkill.exe" 
    | summarize
        taskKillCount = dcount(ProcessCommandLine),
        TaskKillList = make_set(ProcessCommandLine)
        by DeviceId, bin(Timestamp, 2m)
    | where taskKillCount > 10;
// Find attempts to stop processes using net stop
let netStop = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName =~ "net.exe" and ProcessCommandLine has "stop"
    | summarize
        netStopCount = dcount(ProcessCommandLine),
        NetStopList = make_set(ProcessCommandLine)
        by DeviceId, bin(Timestamp, 2m)
    | where netStopCount > 10;
// Look for cipher.exe deleting data from multiple drives
let cipher = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName =~ "cipher.exe" 
    // cipher.exe /w flag used for deleting data 
    | where ProcessCommandLine has "/w" 
    | summarize CipherCount = dcount(ProcessCommandLine), 
        CipherList = make_set(ProcessCommandLine)
        by DeviceId, bin(Timestamp, 1m) 
    // cipher.exe accessing multiple drives in a short timeframe 
    | where CipherCount > 1;
// Look for use of wevtutil to clear multiple logs
let wevtutilClear = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where ProcessCommandLine has "WEVTUTIL" and ProcessCommandLine has "CL"
    | summarize
        LogClearCount = dcount(ProcessCommandLine),
        ClearedLogList = make_set(ProcessCommandLine)
        by DeviceId, bin(Timestamp, 5m)
    | where LogClearCount > 10;
// Look for sc.exe disabling services
let scDisable = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where ProcessCommandLine has "sc"
        and ProcessCommandLine has "config"
        and ProcessCommandLine has "disabled"
    | summarize
        ScDisableCount = dcount(ProcessCommandLine),
        ScDisableList = make_set(ProcessCommandLine)
        by DeviceId, bin(Timestamp, 5m)
    | where ScDisableCount > 10;
// Main query for counting and aggregating evidence
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has_any("list shadows", "delete shadows")
    or FileName =~ "fsutil.exe" and ProcessCommandLine has "usn" and ProcessCommandLine has "deletejournal"
    or ProcessCommandLine has ("bcdedit") and ProcessCommandLine has_any("recoveryenabled no", "bootstatuspolicy ignoreallfailures")
    or ProcessCommandLine has "wbadmin" and ProcessCommandLine has "delete" and ProcessCommandLine has_any("backup", "catalog", "systemstatebackup")
    or (ProcessCommandLine has "wevtutil" and ProcessCommandLine has "cl") 
    or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy delete")
    or (ProcessCommandLine has "sc" and ProcessCommandLine has "config" and ProcessCommandLine has "disabled")
| extend Bcdedit = iff(ProcessCommandLine has "bcdedit" and ProcessCommandLine has_any("recoveryenabled no", "bootstatuspolicy ignoreallfailures"), 1, 0)
| extend ShadowCopyDelete = iff (ProcessCommandLine has "shadowcopy delete", 1, 0)
| extend VssAdminShadows = iff(ProcessCommandLine has "vssadmin" and ProcessCommandLine has_any("list shadows", "delete shadows"), 1, 0)
| extend Wbadmin = iff(ProcessCommandLine has "wbadmin" and ProcessCommandLine has "delete" and ProcessCommandLine has_any("backup", "catalog", "systemstatebackup"), 1, 0)
| extend Fsutil = iff(ProcessCommandLine has "fsutil" and ProcessCommandLine has "usn" and ProcessCommandLine has "deletejournal", 1, 0)
| summarize
    FirstActivity = min(Timestamp),
    ReportId = any(ReportId),
    Commands = make_set(ProcessCommandLine)
    by
    DeviceId,
    Fsutil,
    Wbadmin,
    ShadowCopyDelete,
    Bcdedit,
    VssAdminShadows,
    bin(Timestamp, 6h)
// Joining extra evidence
| join kind=leftouter (wevtutilClear) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (cipher) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (netStop) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (taskKill) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (scDisable) on $left.DeviceId == $right.DeviceId
| extend WevtutilUse = iff(LogClearCount > 10, 1, 0)
| extend CipherUse = iff(CipherCount > 1, 1, 0)
| extend NetStopUse = iff(netStopCount > 10, 1, 0)
| extend TaskkillUse = iff(taskKillCount > 10, 1, 0)
| extend ScDisableUse = iff(ScDisableCount > 10, 1, 0)
// Adding up all evidence
| mv-expand
    CommandList = NetStopList,
    TaskKillList,
    ClearedLogList,
    CipherList,
    Commands,
    ScDisableList
// Format results
| summarize BcdEdit = iff(make_set(Bcdedit) contains "1", 1, 0), NetStop10PlusCommands = iff(make_set(NetStopUse) contains "1", 1, 0), Wevtutil10PlusLogsCleared = iff(make_set(WevtutilUse) contains "1", 1, 0),
    CipherMultipleDrives = iff(make_set(CipherUse) contains "1", 1, 0), Fsutil = iff(make_set(Fsutil) contains "1", 1, 0), ShadowCopyDelete = iff(make_set(ShadowCopyDelete) contains "1", 1, 0),
    Wbadmin = iff(make_set(Wbadmin) contains "1", 1, 0), TaskKill10PlusCommand = iff(make_set(TaskkillUse) contains "1", 1, 0), VssAdminShadow = iff(make_set(VssAdminShadows) contains "1", 1, 0), 
    ScDisable = iff(make_set(ScDisableUse) contains "1", 1, 0), TotalEvidenceCount = count(CommandList), EvidenceList = make_set(Commands), StartofBehavior = min(FirstActivity)
    by DeviceId, bin(Timestamp, 1d)
| extend UniqueEvidenceCount = BcdEdit + NetStop10PlusCommands + Wevtutil10PlusLogsCleared + CipherMultipleDrives + Wbadmin + Fsutil + TaskKill10PlusCommand + VssAdminShadow + ScDisable + ShadowCopyDelete
| where UniqueEvidenceCount > 2

################################################################
#Test-Possible Ransomware Related Destruction Activity
Description
This query identifies common processes run by ransomware 
// malware to destroy volume shadow copies or clean free 
// space on a drive to prevent a file from being recovered 
// post-encryption. To reduce false positives, results are 
// filtered to only actions taken when the initiating 
// process was launched from a suspicious directory. If 
// you don't mind false positives, consider removing the 
// last where clause. // // Special thanks to Captain for additional inputs 
// // This query was updated on 2021-05-19 from https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/tree/master/Execution/Possible%20Ransomware%20Related%20Destruction%20Activity.md

Tactics and techniques
Execution (0)

// # Possible Ransomware Related Destruction Activity
// 
// This query identifies common processes run by ransomware
// malware to destroy volume shadow copies or clean free
// space on a drive to prevent a file from being recovered
// post-encryption.  To reduce false positives, results are
// filtered to only actions taken when the initiating 
// process was launched from a suspicious directory.  If 
// you don't mind false positives, consider removing the 
// last where clause.
// 
// Special thanks to Captain for additional inputs
// 
// This query was updated on 2021-05-19 from https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/tree/master/Execution/Possible%20Ransomware%20Related%20Destruction%20Activity.md
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ 'vssadmin.exe' and ProcessCommandLine has "delete shadows" and ProcessCommandLine has "/all" and ProcessCommandLine has "/quiet") // Clearing shadow copies
    or (FileName =~ 'cipher.exe' and ProcessCommandLine contains "/w") // Wiping drive free space
    or (FileName =~ 'schtasks.exe' and ProcessCommandLine has "/change" and ProcessCommandLine has @"\Microsoft\Windows\SystemRestore\SR" and ProcessCommandLine has "/disable") // Disabling system restore task
    or (FileName =~ 'fsutil.exe' and ProcessCommandLine has "usn" and ProcessCommandLine has "deletejournal" and ProcessCommandLine has "/d") // Deleting USN journal
    or (FileName =~ 'icacls.exe' and ProcessCommandLine has @'"C:\*"' and ProcessCommandLine contains '/grant Everyone:F') // Attempts to re-ACL all files on the C drive to give everyone full control
    or (FileName =~ 'powershell.exe' and (
    ProcessCommandLine matches regex @'\s+-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec)\s+' and replace(@'\x00', '', base64_decode_tostring(extract("[A-Za-z0-9+/]{50,}[=]{0,2}", 0, ProcessCommandLine))) matches regex @".*(Win32_Shadowcopy).*(.Delete\(\)).*"
    ) or ProcessCommandLine matches regex @".*(Win32_Shadowcopy).*(.Delete\(\)).*"
    ) // This query looks for PowerShell-based commands used to delete shadow copies

################################################################
#Test-Suspected exploitation of Log4j vulnerability
Description
Suspected exploitation of Log4j vulnerability

Tactics and techniques
Execution (1)
Initial Access (0)
Lateral Movement (0)

DeviceProcessEvents
| where ProcessCommandLine has_all('${jndi') and ProcessCommandLine has_any('ldap', 'ldaps', 'http', 'rmi', 'dns', 'iiop')
//Removing FPs 
| where not(ProcessCommandLine has_any('stackstorm', 'homebrew')) 


################################################################
#Test-A user is added directly to an Azure AD role, bypassing PIM
Description
Alert when a user is added directly to an Azure AD role, bypassing PIM

Tactics and techniques
Credential Access (0)
Privilege Escalation (0)

//Alert when a user is added directly to an Azure AD role, bypassing PIM
AuditLogs
| where OperationName has "Add member to role outside of PIM"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend UserAdded = tostring(TargetResources[2].displayName)
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project TimeGenerated, OperationName, RoleName, UserAdded, Actor

################################################################
#Test-Computers With Cleaned Event Logs
Description
Report when any computer with cleaned event logs

Tactics and techniques
Initial Access (0)
Privilege Escalation (0)

// Computers With Cleaned Event Logs 
// Computers with cleaned event logs. 
SecurityEvent
| where EventID in (1102, 517) and EventSourceName == 'Microsoft-Windows-Eventlog'
| summarize count() by Computer


################################################################
#Test-Crash dump disabled on host
SecurityEvent
| where EventID == 4657
| parse ObjectName with "\\REGISTRY\\" KeyPrefix "\\" RegistryKey
| project-reorder RegistryKey
| where RegistryKey has "SYSTEM\\CurrentControlSet\\Control\\CrashControl"
| where ObjectValueName =~ "CrashDumpEnabled"
| extend RegistryValueData = iff (OperationType == "%%1906", OldValue, NewValue)
| where RegistryValueData == 0

################################################################
#Test-Execution-File Copy and Execution
Description
This query identifies files that are copied to a device over SMB, then executed within a specified threshold. 
Default is 5 seconds, but is configurable by tweaking the value for ToleranceInSeconds.

Tactics and techniques
Execution (0)
Impact (0)
Lateral Movement (0)
Persistence (0)

let ToleranceInSeconds = 5;
DeviceNetworkEvents
| where LocalPort == 445 and isnotempty(RemoteIP)
| join kind = inner DeviceLogonEvents on DeviceId
| where Timestamp1 between (Timestamp .. datetime_add('second', ToleranceInSeconds, Timestamp)) and RemoteIP endswith RemoteIP1
| join kind=inner (
    DeviceFileEvents
    | where ActionType in ('FileModified', 'FileCreated') and (InitiatingProcessFileName =~ 'System' or InitiatingProcessFolderPath endswith "ntoskrnl.exe")
    )
    on DeviceId
| where Timestamp2 between (Timestamp .. datetime_add('second', ToleranceInSeconds, Timestamp))
| join kind=inner DeviceProcessEvents on DeviceId, FolderPath
| where Timestamp3 between (Timestamp .. datetime_add('second', ToleranceInSeconds, Timestamp))
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    AccountDomain,
    AccountName,
    AccountSid,
    Protocol,
    LogonId,
    RemoteDeviceName,
    IsLocalAdmin,
    FileName,
    FolderPath,
    SHA1,
    SHA256,
    MD5,
    ProcessCommandLine


################################################################
#Test-Malware detection 
Description
Malware detected grouped by threat.
// Malware detection 
// Malware detected grouped by threat. 
// To create an alert for this query, click '+ New alert rule'
ProtectionStatus
| where ThreatStatus != "No threats detected" 
| summarize AggregatedValue = count() by Threat, Computer, _ResourceId

################################################################
#Test-Phishing Mail

let IPList = externaldata(IPAddress: string)[@"https://lists.blocklist.de/lists/mail.txt"] with (format="csv", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
//Network logs
let CSlogSourceIP = CommonSecurityLog
    | summarize by IPAddress = SourceIP, Type;
let CSlogDestIP = CommonSecurityLog
    | summarize by IPAddress = DestinationIP, Type;
let CSlogMsgIP = CommonSecurityLog
    | extend MessageIP = extract(IPRegex, 0, Message)
    | summarize by IPAddress = MessageIP, Type;
let DnsIP = DnsEvents
    | summarize by IPAddress = IPAddresses, Type;
// If you have enabled the imDNS and/or imNetworkSession normalization in your workspace, you can uncomment one or both below.  Reference - https://docs.microsoft.com/azure/sentinel/normalization
//let imDnsIP = imDns (response_has_any_prefix=IPList) | summarize by IPAddress = ResponseName, Type;
//let imNetSessIP = imNetworkSession (dstipaddr_has_any_prefix=IPList) | summarize by IPAddress = DstIpAddr, Type;
//Cloud service logs
let officeIP = OfficeActivity
    | summarize by IPAddress = ClientIP, Type;
let signinIP = SigninLogs
    | summarize by IPAddress, Type;
let nonintSigninIP = AADNonInteractiveUserSignInLogs
    | summarize by IPAddress, Type;
let azureActIP = AzureActivity
    | summarize by IPAddress = CallerIpAddress, Type;
let awsCtIP = AWSCloudTrail
    | summarize by IPAddress = SourceIpAddress, Type;
//Device logs
let vmConnSourceIP = VMConnection
    | summarize by IPAddress = SourceIp, Type;
let vmConnDestIP = VMConnection
    | summarize by IPAddress = DestinationIp, Type;
let iisLogIP = W3CIISLog
    | summarize by IPAddress = cIP, Type;
let devNetIP = DeviceNetworkEvents
    | summarize by IPAddress = RemoteIP, Type;
//need to parse to get IP
let azureDiagIP = AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule") 
    | where msg_s has_any (IPList)
    | parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
    | summarize by IPAddress = DestinationHost, Type;
let sysEvtIP = Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | where EventData has_any (IPList)
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"])
    | where SourceIP in (IPList) or DestinationIP in (IPList)
    | extend IPAddress = iff(SourceIP in (IPList), SourceIP, DestinationIP)
    | summarize by IPAddress, Type;
// If you have enabled the imDNS and/or imNetworkSession normalization in your workdspace, you can uncomment below and include. Reference - https://docs.microsoft.com/azure/sentinel/normalization
//let ipsort = union isfuzzy=true CSlogDestIP, CSlogMsgIP, CSlogSourceIP, DnsIP, officeIP, signinIP, nonintSigninIP, azureActIP, awsCtIP, vmConnDestIP, vmConnSourceIP, azureDiagIP, sysEvtIP, imDnsIP, imNetSessIP
// If you uncomment above, then comment out the line below
let ipsort = union isfuzzy=true
        CSlogDestIP,
        CSlogMsgIP,
        CSlogSourceIP,
        DnsIP,
        officeIP,
        signinIP,
        nonintSigninIP,
        azureActIP,
        awsCtIP,
        vmConnDestIP,
        vmConnSourceIP,
        azureDiagIP,
        sysEvtIP
    | summarize by IPAddress
    | where isnotempty(IPAddress)
    | where not(ipv4_is_private(IPAddress)) and IPAddress !in ('0.0.0.0', '127.0.0.1');
let ipMatch = ipsort
    | where IPAddress in (IPList);
(union isfuzzy=true
    (CommonSecurityLog
    | where SourceIP in (ipMatch) or DestinationIP in (ipMatch) or Message has_any (ipMatch)
    | project TimeGenerated, SourceIP, DestinationIP, Message, SourceUserID, RequestURL, Type
    | extend MessageIP = extract(IPRegex, 0, Message)
    | extend IPMatch = case(SourceIP in (ipMatch), "SourceIP", DestinationIP in (ipMatch), "DestinationIP", MessageIP in (ipMatch), "Message", "No Match")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, IPMatch == "Message", MessageIP, "No Match")
    ),
    (OfficeActivity
    | where ClientIP in (ipMatch)
    | project TimeGenerated, UserAgent, Operation, RecordType, UserId, ClientIP, Type
    | extend SourceIPAddress = ClientIP, Account = UserId
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = SourceIPAddress,
        AccountCustomEntity = Account
    ),
    (DnsEvents
    | where IPAddresses has_any (ipMatch)
    | project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
    | extend DestinationIPAddress = IPAddresses, Host = Computer
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = DestinationIPAddress,
        HostCustomEntity = Host
    ),
    (VMConnection
    | where SourceIp in (ipMatch) or DestinationIp in (ipMatch)
    | project TimeGenerated, Computer, SourceIp, DestinationIp, Type
    | extend IPMatch = case(SourceIp in (ipMatch), "SourceIP", DestinationIp in (ipMatch), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "None"),
        Host = Computer
    ),
    (Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | where EventData has_any (ipMatch)
    | project TimeGenerated, EventData, UserName, Computer, Type
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"])
    | where SourceIP in (ipMatch) or DestinationIP in (ipMatch)
    | extend IPMatch = case(SourceIP in (ipMatch), "SourceIP", DestinationIP in (ipMatch), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserName,
        HostCustomEntity = Computer,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
    ),
    (SigninLogs
    | where IPAddress in (ipMatch)
    | project TimeGenerated, UserPrincipalName, IPAddress, Type
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress
    ),
    (AADNonInteractiveUserSignInLogs
    | where IPAddress in (ipMatch)
    | project TimeGenerated, UserPrincipalName, IPAddress, Type
    | extend
        timestamp = TimeGenerated,
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress
    ),
    (W3CIISLog
    | where cIP in (ipMatch)
    | project TimeGenerated, Computer, cIP, csUserName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = cIP,
        HostCustomEntity = Computer,
        AccountCustomEntity = csUserName
    ),
    (AzureActivity
    | where CallerIpAddress in (ipMatch)
    | project TimeGenerated, CallerIpAddress, Caller, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = CallerIpAddress,
        AccountCustomEntity = Caller
    ),
    (
    AWSCloudTrail
    | where SourceIpAddress in (ipMatch)
    | project TimeGenerated, SourceIpAddress, UserIdentityUserName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = SourceIpAddress,
        AccountCustomEntity = UserIdentityUserName
    ), 
    ( 
    DeviceNetworkEvents
    | where RemoteIP in (ipMatch)
    | project TimeGenerated, RemoteIP, DeviceName, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = RemoteIP,
        HostCustomEntity = DeviceName
    ),
    (
    AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule")
    | where msg_s has_any (ipMatch)
    | project TimeGenerated, msg_s, Type
    | parse msg_s with Protocol 'request from ' SourceIP ':' SourcePort 'to ' DestinationIP ':' DestinationPort '. Action:' Action
    | where DestinationIP has_any (ipMatch)
    | extend timestamp = TimeGenerated, IPCustomEntity = DestinationIP
    )
// If you have enabled the imDNS and/or imNetworkSession normalization in your workdspace, you can uncomment below and include. Reference - https://docs.microsoft.com/azure/sentinel/normalization
//,
//(imDns (response_has_any_prefix=IPList)
//| project TimeGenerated, ResponseName, SrcIpAddr, Type
//| extend DestinationIPAddress = ResponseName,  Host = SrcIpAddr
//| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress, HostCustomEntity = Host
//),
//(imNetworkSession (dstipaddr_has_any_prefix=IPList)
//| project TimeGenerated, DstIpAddr, SrcIpAddr, Type
//| extend timestamp = TimeGenerated, IPCustomEntity = DstIpAddr, HostCustomEntity = SrcIpAddr
//)
)

      
################################################################
#Test-Unauthorized (rejected) connection attempts
Description
Search for unauthorized (rejected) connection attempts

Tactics and techniques
Discovery (1)
// Unauthorized connections 
// Search for unauthorized (rejected) connection attempts. 
// To create an alert for this query, click '+ New alert rule'
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" 
| where Category == "PostgreSQLLogs"
| where Message contains "password authentication failed" or Message contains "no pg_hba.conf entry for host"

################################################################
#Test-Unauthorized Users
Description
Get a list of unauthorized users with their request count in last 24 hours

Tactics and techniques
Credential Access (1)
T1040 - Network Sniffing
Discovery (1)

// Unauthorized Users 
// Get a list of unauthorized users with their request count in last 24 hours. 
LAQueryLogs
| where ResponseCode == "403"
| summarize reqCount = count() by AADObjectId
| order by reqCount desc

################################################################
#Test-Accounts Terminated Antimalware
Description
Accounts which terminated Microsoft Antimalware. Report when Microsoft Antimalware Real-Time Protection feature has encountered an error and failed.
// Accounts Terminated Antimalware 
// Accounts which terminated Microsoft Antimalware. 
SecurityEvent
| where EventID == 4689
| where Process has "MsMpEng.exe" or ParentProcessName has "MsMpEng.exe"
| summarize TerminationCount = count() by Account

################################################################
#Test-Tracking Password Changes

Description
Tracking Password Changes

Tactics and techniques
Credential Access (1)
T1110 - Brute Force
Initial Access (1)

let action = dynamic(["change ", "changed ", "reset "]);
let pWord = dynamic(["password ", "credentials "]);
(union isfuzzy=true
    (SecurityEvent
    | where EventID in (4723, 4724)
    | summarize
        StartTimeUtc = min(TimeGenerated),
        EndTimeUtc = max(TimeGenerated),
        ResultDescriptions = makeset(Activity),
        ActionCount = count()
        by
        Resource = Computer,
        OperationName = strcat("TargetAccount: ", TargetUserName),
        UserId = Account,
        Type
    ),
    (AuditLogs
    | where OperationName has_any (pWord) and OperationName has_any (action)
    | extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) 
    | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName) 
    | where ResultDescription != "None" 
    | summarize
        StartTimeUtc = min(TimeGenerated),
        EndTimeUtc = max(TimeGenerated),
        ResultDescriptions = makeset(ResultDescription),
        CorrelationIds = makeset(CorrelationId),
        ActionCount = count()
        by
        OperationName = strcat(Category, " - ", OperationName, " - ", Result),
        Resource,
        UserId = TargetUserPrincipalName,
        Type
    | extend ResultDescriptions = tostring(ResultDescriptions)
    ),
    (OfficeActivity
    | where (ExtendedProperties has_any (pWord) or ModifiedProperties has_any (pWord)) and (ExtendedProperties has_any (action) or ModifiedProperties has_any (action))
    | extend ResultDescriptions = case(
        OfficeWorkload =~ "AzureActiveDirectory", tostring(ExtendedProperties),
        OfficeWorkload has_any ("Exchange", "OneDrive"), OfficeObjectId,
        RecordType) 
    | summarize
        StartTimeUtc = min(TimeGenerated),
        EndTimeUtc = max(TimeGenerated),
        ResultDescriptions = makeset(ResultDescriptions),
        ActionCount = count()
        by
        Resource = OfficeWorkload,
        OperationName = strcat(Operation, " - ", ResultStatus),
        IPAddress = ClientIP,
        UserId,
        Type
    ),
    (Syslog
    | where SyslogMessage has_any (pWord) and SyslogMessage has_any (action)
    | summarize
        StartTimeUtc = min(TimeGenerated),
        EndTimeUtc = max(TimeGenerated),
        ResultDescriptions = makeset(SyslogMessage),
        ActionCount = count()
        by
        Resource = HostName,
        OperationName = Facility,
        IPAddress = HostIP,
        ProcessName,
        Type
    ),
    (SigninLogs
    | where OperationName =~ "Sign-in activity" and ResultType has_any ("50125", "50133")
    | summarize
        StartTimeUtc = min(TimeGenerated),
        EndTimeUtc = max(TimeGenerated),
        ResultDescriptions = makeset(ResultDescription),
        CorrelationIds = makeset(CorrelationId),
        ActionCount = count()
        by
        Resource,
        OperationName = strcat(OperationName, " - ", ResultType),
        IPAddress,
        UserId = UserPrincipalName,
        Type
    )
)
| extend
    timestamp = StartTimeUtc,
    AccountCustomEntity = UserId,
    IPCustomEntity = IPAddress

################################################################
#
################################################################
#
