# Malware Analysis of "Silentnet" Infostealer.

## Overview of how it works:
Once user signs up on their website, They are given a unique UUID (User Id) which helps the malware identify who it belongs to once built. After the malware is executed it knows where and who it has to send those logs to, logs containing account credentials.

Silentnet can be either built as .exe or a .jar file, i won't be covering the .exe in this blog

## silentnet.jar

### File Structure
<img width="1140" height="477" alt="image" src="https://github.com/user-attachments/assets/b5334344-7db7-4c83-9d2b-f026f619021f" />

```
silentnet.jar
├── META-INF/MANIFEST.MF              ← Main-Class: com.github.kN3_T1SUn
├── fabric.mod.json                   ← Fabric entrypoint: com.github.rhdbning
├── LICENSE_github                    ← decoy license 
├── assets/package/icon.png           ← decoy mod icon
└── com/github/
    ├── kN3_T1SUn.class                 ← Launcher helper
    ├── rhdbning.class                  ← Fabric entrypoint 
    ├── Ab7OvKpD_uT.class               ← C2 dispatcher + payload downloader
    ├── sIOGnGMy5.class                 ← HTTP client + Handshake domain resolver
    ├── sIOGnGMy5$findJaluzaur.class    ← inner class 
    ├── sIOGnGMy5$tzzyOarmlgPm.class    ← inner class 
    └── sIOGnGMy5$xs_vojl.class         ← inner class 
```

#### rhdbning — Fabric entrypoint

Implements `net.fabricmc.api.ModInitializer`. The `onInitialize()` method:

1. Spawns a background Thread.
2. Inside the thread:
   ```java
   class_320 session = class_310.method_1551().method_1548();  // MinecraftClient.getInstance().getSession()
   String username = session.method_1674();                     // getAccessToken()
   String uuid     = session.method_1676();                     // getUsername()
   UUID sessionUuid = session.method_44717();                   // getUuidOrNull() 
   (`class_310` is Minecraft's `MinecraftClient`, `class_320` is `Session` — Fabric's intermediary mappings hide the real names.)
3. Reads the current game directory via `FabricLoader.getInstance().getConfigDir().getParent()`.
5. Creates the registration data (JSON) and sends it to the C2 server.
6. AES-decrypts the response and extracts the Stage-3 download URL.
7. Downloads `main.py` + `jre-embedded`, spawns `python.exe main.py`.

#### `sIOGnGMy5` — HTTP client + Handshake domain resolver
Implements its own HTTP/1.1 client on raw `SSLSocket`. Key methods

1. Checks if hostname is already an IP literal - returns it directly.
2. Checks in-memory cache - returns cached IP if not expired.
3. Builds a DNS wire-format query by hand
4. Base64url encodes the query.
5. Sends HTTPS GET to `https://cloudflare-dns.com/dns-query?dns=<b64>`


### Ab7OvKpD_uT - C2 Dispatcher

1. Gets a c2 from **`getDomain()`**.
2. Builds the JSON: `{"mcInfo":"...","prefireId":"...","userId":"...","tag":"...","domain":"...","gameDir":"...","mcUuid":"...","env":"Fabric"}`
3. Sends a POST Request to C2

### payload downloader
1. https://thisisafalsepositive.st/cdn/e/42a522313d92 (main.py)
2. https://thisisafalsepositive.st/cdn/e/36f2c0035ef9 (app.pyd)

### How to recognise silentnet while checking files manually:
Silentnet injects safe mods with malicious code, It always adds itself as a "github" folder (com/github/) and the .class file names are always different, But the obfuscation and the methods inside are still the same.

