---
layout: default
---


Hello.
In this blog, I will be covering various Java malware families distributed as .jar files, along with detailed analyses of each.

You can also visit and use our [static malware analyzer for .jar files](https://www.jarscanner.org/)

### Here is the list of all malware families i have covered so far:

- # [SILENTNET (updated)](./silentnet.html)
The most up-to-date and detailed analysis of SilentNet, a large Malware-as-a-Service operation primarily targeting the Minecraft community through malicious .jar files.

---

- # [JRAT](./jrat.html)
Deep analysis of Jrat, Its multi stage loading architecture, heavy obfuscation techniques, use of encrypted embedded payloads, RSA+AES
cryptographic protection of its configuration, and anti analysis countermeasure.

---

- # [XARID](./xarid.html)
Xarid is a Java trojan dropper targeting Uzbek speaking Windows users. It disguises itself as a financial/tax inspection tool, when executed, displays a fake Uzbek tax warning. Once the user clicks "Accept," it silently downloads malicious components from its C2 server, then establishes dual persistence to survive reboots.

---

- # [CROWC](./crowcontrol.html)
Crowc, also known as CrowControl is the newest malware family / MaaS for .jar files as of August 28th 2026. Although i did not have the .jar sample of this MaaS during the analysis, So i had to analyze their .exe sample instead.
