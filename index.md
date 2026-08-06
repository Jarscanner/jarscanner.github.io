---
layout: default
---


Hello.
In this blog, I will be covering various Java malware families distributed as .jar files, along with detailed analyses of each.

You can also visit and use our [static malware analyzer for .jar files](https://www.jarscanner.org/)

### Here is the list of all malware families i have covered so far:

# [SILENTNET](./silentnet.html)
There are already multiple malware analysis of this family, But i decided to make one anyways. Silentnet is a MaaS (Malware-as-a-Service), The malware disguises itself as a legit Minecraft mod while also executing malicious code under the hood. 

---

# [JRAT](./jrat.html)
Deep analysis of Jrat, Its multi stage loading architecture, heavy obfuscation techniques, use of encrypted embedded payloads, RSA+AES
cryptographic protection of its configuration, and anti analysis countermeasure.

---

# [XARID](./xarid.html)
Xarid is a Java trojan dropper targeting Uzbek speaking Windows users. It disguises itself as a financial/tax inspection tool, when executed, displays a fake Uzbek tax warning. Once the user clicks "Accept," it silently downloads malicious components from its C2 server, then establishes dual persistence to survive reboots.
