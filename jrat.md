# Malware Analysis of "Jrat" Remote Access Trojan.

This report provides a detailed technical analysis of the JRat malware sample. The analysis covers its
multi stage loading architecture, heavy obfuscation techniques, use of encrypted embedded payloads, RSA+AES
cryptographic protection of its configuration, and anti analysis countermeasures. The sample is a
Java Remote Access Trojan (RAT) designed to establish persistent unauthorized remote control over
compromised systems.

---

## 1. Executive Summary

The analyzed sample, JRat.jar, is a Java based Remote Access Trojan (RAT) that
employs a sophisticated multi stage loading architecture designed to evade detection by antiviruses
and frustrate manual reverse engineering efforts. The malware uses a combination of extreme identifier
obfuscation, encrypted embedded payloads, RSA+AES hybrid encryption for its configuration data, and a custom
classloader chain to dynamically decrypt and execute its core malicious payload at runtime. The total unpacked size
of the malicious code spans over 475 KB across 37 files, with the actual RAT payload hidden within an encrypted
JAR file that is embedded as a resource and decrypted only during execution.

The initial entry point triggers a dual execution path: one branch extracts and launches an embedded JAR as a
separate Java process via ProcessBuilder, while the other branch invokes a custom classloader chain that reads
encrypted resources, decrypts them using RSA private keys and AES symmetric ciphers, loads the decrypted classes
into memory via a custom URLClassLoader, and then uses reflection to locate and invoke the RAT payload's
main() method. This dual path approach ensures that even if one execution vector is blocked or fails, the malware
can still achieve its objectives through the alternate path, increasing its resilience against security
countermeasures.

The obfuscation is heavy even by Java malware standards. All 33 classes in the payload package are named with
a long repeated string pattern, Java reserved keywords are used as field and method names (break, void,
super, enum), and embedded resources are disguised as cloud service filenames (drop.box, sky.drive,
mega.download). Configuration data including the C2 server path, authentication password, and cryptographic keys
are stored as encrypted serialized Java objects and XML properties, making static extraction of
command-and-control indicators difficult without runtime analysis or possession of the RSA private key. 
It including anti analysis, encrypted C2 channels, and an architecture that allows the actual malicious functionality (screen capture, keylogging, file
exfiltration, remote shell, etc.) to be hidden within the encrypted payload that could not be fully decrypted during
static analysis.

---

## 2. File Metadata and Indicators of Compromise

### 2.1 Sample Information
<img width="1135" height="560" alt="image" src="https://github.com/user-attachments/assets/aebe04eb-c51d-4f64-8b35-e49e2dfe4206" />


| Item | Value |
|---|---|
| Filename | `JRat.jar` |
| Size | `490,909 bytes (479 KB)` |
| Type | `Java Archive (JAR), Zip-based` |
| Build Tool  | `Apache Ant 1.8.0` |
| Java Version | `1.8.0_25-b18 (Oracle Corporation` |
| Main-Class (Manifest) | `operational.Jrat` |
| Total Entries | `37 files (3 operational + 33 obfuscated + 3 data + 2 meta)` |

### 2.2 Hash Digests

| Item | Value |
|---|---|
| SHA-256 | `693d967c110eff019853d2a92d77447bcfb2ea2306036644c97d7353a9898662` |
| SHA-1 | `9d277b8c0a7956f809264b38d77e8e7e42f40cf1` |
| MD5 | `83f12a0935935b7b3048d8a3272fd386` |

### 2.3 Embedded Resource Files

The JAR contains several embedded files with deceptive names. These
files contain encrypted cryptographic material and configuration data essential for the malware's operation.

| Filename | Type | Size | Purpose |
|---|---|---|---|
| drop.box | `Encrypted binary data` | `368 bytes` | AES encrypted config or key material |
| sky.drive | `Java serialized KeyRep` | `1,475 bytes` | RSA private key (serialized java.security.KeyRep) |
| mega.download | `Encrypted binary data` | `256 bytes` | AES encrypted password/token |
| Rb/GIh/Wgv.xKF | `Encrypted binary data` | `224,928 bytes` | Primary encrypted payload/resource |
| U/cK/aQw.VD | `Java serialized KeyRep` | `1,476 bytes` | Secondary RSA key material |
| jX/nyA/DFr.Imv | `Encrypted binary data` | `256  bytes` | Auxiliary encrypted data block |
| operational/iiiiiiiiii.class | `Embedded JAR (PK magic)` | `247,088 bytes` | Full encrypted JAR payload |

## 3. Execution Flow Analysis

The malware implements multi stage loading process. After execution, the Java runtime
loads the operational.Jrat class, which serves as the primary entry point. 
This class implements a dual execution strategy to increase the chances of successful payload
delivery even if one path is interrupted by security measures or environmental constraints on the target system.

### 3.1 Stage 1: Dual Path Initial Loader (Jrat.class)

The **Jrat.class** entry point executes two distinct code paths. The first path attempts to extract an
embedded resource (/operational/iiiiiiiiii.class), which is a fully contained JAR file disguised with a
generic class filename. It writes this embedded JAR to a temporary file with a randomized name (using
Math.random() in the filename), then launches it as a separate Java process using ProcessBuilder, explicitly
locating the Java binary from the system's java.home property. This process spawning technique is a common
malware persistence and sandbox evasion tactic, as the child process may execute in a different security context
than the parent.

The second path uses Java reflection to load and invoke operational.JRat.class's main() method. This adds another layer of indirection that can confuse static analysis tools and stack trace
inspection. Both paths are wrapped in `try-catch` blocks that silently swallow all exceptions, ensuring the malware
fails without producing error messages or crash dumps that could alert the user to its
presence on the system.

### 3.2 Stage 2: Encrypted Payload Bootstrap (JRat.class)

The JRat.class instantiates the core loader chain. It begins by loading three encrypted resources from
within the JAR file using JRat.class.getResourceAsStream(). These resources correspond to the C2
configuration paths discovered in the code: /sky.drive, /mega.download, and /drop.box. The loader reads
these resources as byte arrays, then constructs a decryption pipeline using the cryptographic engine (class l) and the
properties reader (class s).

The decryption process uses a hybrid RSA+AES scheme. An RSA private key (serialized as a
java.security.KeyRep object in the sky.drive file) is first decrypted, then used to unwrap an AES key stored
in mega.download. This AES key is then used to decrypt the actual configuration data from drop.box, which
contains the server connection details and authentication credentials in XML properties format. The configuration is
loaded via Properties.loadFromXML(), extracting three critical values: PRIVATE_PASSWORD,
PASSWORD_CRYPTED, and SERVER_PATH

### 3.3 Stage 3: Custom ClassLoader Chain

After decrypting the configuration, the malware constructs a custom classloader hierarchy: v (base
URLClassLoader) -> x (decryption-aware resource loader) -> j (custom findClass implementation) -> g (payload
launcher). Class x overrides getResourceAsStream() to intercept all resource loading requests, transparently
decrypting encrypted resources before returning them as ByteArrayInputStream objects. This
means that any class loaded through this chain automatically receives decrypted bytecode without the payload
classes themselves needing to contain any decryption logic.

Class e (the JAR unpacker) reads the embedded JAR payload, iterating through its entries using a custom
JarInputStream. It extracts the Main Class attribute from the embedded JAR's manifest, reads each class entry
into memory, and stores the encrypted bytecode in a HashMap cache keyed by class name. Finally, class g loads
the main class from this cache, locates its main(String[]) method via reflection (building the method name
character by character: {'m','a'} + {'i','n'} = "main"), and invokes it with Method.invoke(null, new
String[]{}), transferring execution to the actual RAT payload.

## 4. Obfuscation

The obfuscation employed by this sample is heavy and multi layered, designed to confuse both automated
analysis tools and human reverse engineers. The techniques range from name mangling to 
structural deception, creating a significant barrier to timely and accurate threat assessment. Understanding these
obfuscation methods is essential for developing effective detection signatures and for recognizing related samples in
the wild that may share the same obfuscation framework.

### 4.1 Identifier Obfuscation

All 33 classes in the w package share an identical class name prefix of 127 characters: a repeated pattern of
"maninthesky" with slight variations. The full class name for each class exceeds 200 characters when the package
prefix is included. This makes the JAR entries visually indistinguishable in file listings, extremely difficult to
reference in analysis tools, and impossible to search for using standard text based detection rules. The
repetition of "man in the sky" suggests a custom obfuscation tool or script specifically designed for this malware
family, as no publicly available Java obfuscator produces this particular naming pattern.

### 4.2 Java Reserved Keyword Abuse

The decompiled code reveals that the malware uses Java reserved keywords as field, method, and local variable
names. Fields are named break, void, enum, and super. Method parameters uniformly use the name
maninthesky. This technique is particularly insidious because it causes many decompilers to produce
syntactically invalid or misleading Java code, complicating manual analysis. CFR flagged this with the comment
"Illegal identifiers - consider using --renameillegalidents true," confirming that this is an intentional
anti decompilation measure.

### 4.3 Deceptive Filenames

The embedded resources use filenames that mimic popular cloud storage services: drop.box, sky.drive, and
mega.download. Similarly, the large encrypted payload is stored as Rb/GIh/Wgv.xKF with a non Java file
extension. The embedded JAR is named iiiiiiiiii.class, mimicking a class file while actually being a complete JAR
archive (identified by the PK magic bytes 50 4B 03 04). This naming deception is designed to evade file type based
detection heuristics and to appear innocuous during inspection of the JAR contents.

### 4.4 Junk Code and Dead Code Insertion

Throughout the decompiled code, there are numerous instances of apparently useless object instantiations. Class h
(the anti-analysis wrapper) is instantiated repeatedly between critical operations, creating a large number of
timestamped objects that serve no functional purpose. Class b contains three empty methods (P(), x(), S()).
Classes r, ka, and fa are entirely empty placeholder classes. This technique inflates the codebase, wastes analyst
time and can confuse control flow analysis tools.

### 4.5 Character by Character String Construction

Sensitive strings are never stored as complete literals in the code. Instead, they are assembled character by character
from char arrays at runtime. The method name "main" is built as {'m','a'} + {'i','n'}, "Main-Class" as "Ma" + "in" +
"-Cla" + "ss", and ".class" as "." + "c" + "la" + "ss". This technique defeats static string based detection (such as
YARA rules) and prevents automated tools from displaying the complete strings in their output.

## 5. Cryptographic Analysis

The malware employs a hybrid RSA+AES encryption scheme to protect its configuration data, including the C2
server address, authentication credentials, and operational parameters. This approach provides both strong
protection of the configuration data (via RSA) and efficient decryption of the actual payload (via AES). The use of
standard Java cryptographic APIs (javax.crypto.Cipher, java.security.Key) ensures the malware operates on any
platform supporting Java 8 without requiring native libraries.

### 5.1 Key Management Architecture

The cryptographic key material is stored in multiple serialized files within the JAR. The sky.drive and
U/cK/aQw.VD files contain Java serialized java.security.KeyRep objects, which are the standard Java
serialization format for cryptographic keys. The KeyRep objects identified in the hex dumps confirm these are RSA
private keys. These private keys are used to decrypt the AES session keys stored in mega.download and
drop.box, which are 256-byte blocks consistent with AES-256 encrypted data.

### 5.2 Decryption Pipeline

The decryption engine (class l) implements the complete pipeline. It first creates an RSA cipher using
Cipher.getInstance("RSA"), initializes it with the private key for decryption (mode 2 =
Cipher.DECRYPT_MODE), and uses it to unwrap the AES key. It then creates an AES cipher using
Cipher.getInstance("AES"), initializes it with the unwrapped AES key (also mode 2), and decrypts the
encrypted configuration data. The result is returned as a ByteArrayInputStream for consumption by the
properties reader. The standard cryptographic algorithms suggest the author prioritized reliability over custom,
potentially detectable schemes.

### 5.3 Configuration Protection

The decrypted configuration contains three critical properties: PRIVATE_PASSWORD,
PASSWORD_CRYPTED, and SERVER_PATH. The presence of both a plaintext password and a crypted
password variant suggests the malware supports multiple authentication methods, possibly for backward
compatibility. The SERVER_PATH likely contains a relative URL path for C2 registration. The XML properties
format allows easy extension with additional parameters in future variants.

## 6. Payload Architecture

The actual malicious payload is not directly visible through static analysis because it is stored as an encrypted JAR
file within the outer JAR. The payload JAR (Rb/GIh/Wgv.xKF, 224,928 bytes) and its duplicate (iiiiiiiiii.class,
247,088 bytes) contain the same set of obfuscated classes along with an additional entry point. The payload's main
class is loaded via reflection and executed with a new empty String array, indicating it is self contained and requires
no command line parameters.

### 6.1 Loader Class Hierarchy

| Class (Short) | Extends | Role |
|---|---|---|
| v | `URLClassLoader` | `Base classloader with HashMap cache and configuration fields` | 
| x | `v` | `Overrides getResourceAsStream() for decryption` | 
| j | `x` | `Overrides findClass() to load classes from encrypted cache` | 
| g | `j` | `Payload launcher: loads main class, invokes main() via reflection` | 
| e | `(standalone)` | `JAR unpacker: reads encrypted JAR entries into HashMap cache` | 
| l | `(standalone)` | `Cryptographic engine: RSA+AES hybrid decryption pipeline` | 
| s | `Properties` | `Configuration reader: loads decrypted XML properties` |
| k | `(standalone)` | `InputStream-to-byte[] reader for reading JAR entries` | 
| u | `HashMap` | `Encrypted class bytecode cache keyed by class name` | 
| o | `JarInputStream` | `Custom JarInputStream with anti-debug hooks on close` | 
| t | `Manifest` | `Manifest reader: extracts Main-Class from embedded manifest` | 
| n | `(static)` | `Resource accessor: loads resources via getResourceAsStream()` |
| d | `(static)` | `Reflection helper: invokes Method.invoke(null, args)` |
| f | `(static)` | `ProtectionDomain accessor: provides code source for defineClass()` |
| q | `ObjectInputStream` | `ProtectionDomain accessor: provides code source for defineClass()` |
| h | `(wrapper)` | `String wrapper with anti-debug timestamped objects` |
| c | `(static)` | `Path converter: replaces "/" with "." for class name resolution` |
| m | `(static)` | `Class name normalizer: strips ".class" suffix` |

## 7. Network Communication Indicators

I couldnt find direct network communication code in the decompiled loader/stub classes. However, the presence of
a `SERVER_PATH` configuration property and the overall RAT architecture strongly indicates that the actual
payload (hidden within the encrypted embedded JAR) implements the C2 communication protocol. The loader's
sole purpose is to decrypt, load, and execute this payload, which would then establish the actual network connection
to the C2 server.

### 7.1 Identified C2 Related Configuration Keys

| Configuration Key | Likely Purpose | Notes |
|---|---|---|
| SERVER_PATH | `C2 server endpoint/path` | `Relative URL path combined with base address` | 
| PRIVATE_PASSWORD | `RAT authentication password` | `Used to authenticate to C2 server` | 
| PASSWORD_CRYPTED | `Encrypted password variant` | `Alternate or backup auth credential` | 
| /sky.drive | `C2 communication path #1 ` | `Named to mimic Microsoft OneDrive` | 
| /mega.download  | `C2 communication path #2` | `Named to mimic Mega cloud service` | 
| /drop.box | `C2 communication path #3` | `Named to mimic Dropbox` | 

### 7.2 Resource Files as C2 Disguise

The use of cloud service names for C2 communication paths is a deliberate evasion technique. If network traffic
inspection reveals connections to paths ending in /sky.drive, /mega.download, or /drop.box, these could
easily be mistaken for legitimate cloud storage API calls. This technique is particularly effective in enterprise
environments where cloud storage services are commonly permitted through firewalls. Security teams should
consider these path names as potential indicators of compromise when observed in unexpected contexts, although I am not 100% sure in this.

## 8. Anti Analysis and Evasion Techniques

The malware has multiple layers of anti analysis protection, ranging from passive obfuscation measures to
active runtime countermeasures. These techniques are designed to increase the time and expertise required for
thorough analysis, delay detection, and reduce the likelihood of accurate threat intelligence extraction.

| Technique | Implementation | Effectiveness |
|-----------|----------------|---------------|
| **Extreme Class Name Obfuscation** | Uses a 127 character repeated `maninthesky` prefix for class names. | **High** – Defeats string-based detection and signature matching. |
| **Reserved Keyword Abuse** | Fields are named using Java reserved keywords such as `break`, `void`, `enum`, and `super`. | **Medium** – Breaks or confuses decompiler output. |
| **Deceptive Filenames** | Cloud service names are used for C2-related paths and resources. | **High** – Helps evade URL- and filename-based detection. |
| **JAR-within-JAR Nesting** | An embedded JAR is disguised as a `.class` file within the main archive. | **Medium** – Hides the payload from casual inspection and static analysis. |
| **Silent Exception Swallowing** | Empty `catch` blocks are used throughout the codebase. | **High** – Prevents error-based detection and reduces observable failures. |
| **Process Spawning** | Uses `ProcessBuilder` to launch a child process. | **High** – Can aid in sandbox evasion and process isolation. |
| **Reflection-Based Invocation** | Uses `Method.invoke()` to launch the payload indirectly. | **High** – Hides call relationships and complicates static analysis. |
| **Junk Code Insertion** | Inserts unnecessary object creation and no-op operations between meaningful instructions. | **Medium** – Wastes analyst time and increases decompilation noise. |
| **Anti-Timestamp Objects** | Repeated creation of `h()` objects throughout execution. | **Low–Medium** – May interfere with debugging or timing-based analysis. |
| **Hybrid RSA + AES Encryption** | Configuration data and payload are fully encrypted using a hybrid cryptographic scheme. | **Very High** – Prevents static extraction of sensitive data and payloads. |
| **Dynamic Class Loading** | Uses a custom `URLClassLoader` combined with runtime decryption to load classes dynamically. | **Very High** – Payload is decrypted and loaded at runtime rather than existing on disk. |

## 9. Class Inventory and Role Mapping

The following table provides a complete inventory of all classes discovered in the JAR, mapped to their functional
roles within the malware architecture. Classes are organized by their role category: entry points, cryptographic
operations, classloading infrastructure, JAR handling, anti-analysis, and utility functions. Each class size provides an
indication of its complexity.

| Class | Approx. Size | Category | Role |
|------|-------------:|----------|------|
| **JRat** | ~600 bytes | Entry | Payload bootstrap. |
| **Jrat** | ~1,200 bytes | Entry | Initial loader that launches the embedded JAR. |
| **z** | 4,484 bytes | Core | Reads configuration and launches the payload. |
| **e** | 4,233 bytes | Core | Unpacks the embedded JAR and reads entries into cache. |
| **l** | 1,599 bytes | Crypto | RSA + AES decryption engine. |
| **g** | 2,707 bytes | Loader | Launches the payload using reflection. |
| **j** | 2,895 bytes | Loader | Custom class loader implementing `findClass()`. |
| **x** | 2,140 bytes | Loader | Resource loader with transparent runtime decryption. |
| **v** | 2,196 bytes | Loader | Base `URLClassLoader` implementation. |
| **o** | 1,406 bytes | I/O | Custom `JarInputStream` implementation. |
| **p** | 1,189 bytes | I/O | Wrapper around `JarInputStream`. |
| **a** | 1,348 bytes | I/O | Custom `JarEntry` wrapper. |
| **t** | 2,127 bytes | I/O | Manifest reader. |
| **k** | 900 bytes | I/O | Utility for reading `InputStream` objects. |
| **n** | 1,403 bytes | Resource | Resource accessor. |
| **s** | 1,187 bytes | Config | XML/Properties configuration reader. |
| **q** | 837 bytes | Serialization | `ObjectInputStream` wrapper. |
| **i** | 1,081 bytes | Config | Stores constants such as C2 paths and passwords. |
| **aa** | 736 bytes | Crypto | Cipher factory. |
| **pa** | 723 bytes | Crypto | Cipher wrapper. |
| **u** | 957 bytes | Cache | Encrypted bytecode `HashMap` cache. |
| **h** | 1,114 bytes | Anti-Analysis | Anti-debug string wrapper. |
| **b** | 421 bytes | Junk | Empty dead code. |
| **c** | 487 bytes | Utility | Path converter. |
| **d** | 1,031 bytes | Utility | Reflection helper. |
| **f** | 570 bytes | Utility | `ProtectionDomain` accessor. |
| **m** | 934 bytes | Utility | Class name normalizer. |
| **y** | 474 bytes | Utility | Generic object wrapper. |
| **sa** | 570 bytes | Stream | `ByteArrayInputStream` subclass. |
| **qa** | 436 bytes | Stream | `ByteArrayOutputStream` subclass. |
| **r** | 423 bytes | Junk | Empty marker class. |
| **w** | 436 bytes | Error | Custom `ClassNotFoundException`. |
| **fa** | 487 bytes | Junk | Empty thread implementation. |
| **ka** | 423 bytes | Junk | Empty placeholder class. |

## 10. Detection and Mitigation Recommendations

### 10.1 YARA Detection Rules

The following YARA rules can detect this malware and likely variants. They target the unique class naming pattern,
deceptive filenames, and specific Java bytecode patterns observed during analysis. 
```
rule JRat_RAT_Loader { meta: description = "Detects JRat-RAT Java malware" severity = "critical"
condition: uint16(0) == 0xCAF0 and "manintheskymanintheskymaninthesky" and "drop.box" and
"sky.drive" and "mega.download" and "operational.JRat" or "operational.Jrat" }
```
### 10.2 Network Detection

Network-based detection should focus on the suspicious URL path patterns used for C2 communication. Configure
IDS/IPS rules and proxy logging to flag connections containing these paths, particularly from Java processes or
unexpected endpoints. SSL/TLS inspection should monitor handshake patterns associated with the C2 server
```
Network IOCs (path patterns): GET/POST /*/sky.drive GET/POST /*/mega.download GET/POST
/*/drop.box
```

-thank you for reading
