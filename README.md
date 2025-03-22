# IROAD X Series

Product: https://www.iroadau.com.au

## Finding 1 - CVE-2025-2341: Default credentials for SSID [CWE-1393]
The IROAD X5 dashcam broadcasts a fixed SSID with default credentials that cannot be changed. This allows any nearby attacker to connect to the dashcam’s network without restriction. Once connected, an attacker can sniff on connected devices such as the user’s smartphone. The SSID is also always broadcasted.

## Finding 2 - CVE-2025-2342: Hardcoded credentials in APK (IROAD <= v5.2.5) to ports 9091 and 9092
The IROAD X5 mobile application (version 5.2.5 and below) contains hardcoded credentials that provide unauthorized access to the dashcam's API endpoints on ports 9091 and 9092:

a) Once IRoad SSID is connected to, the attacker sends a crafted authentication command with "TibetList" and "000000" to list settings of the dashcam at port 9091. 

b) There's a separate set of credentials for port 9092 (stream) that is exposed in plaintext as well, "admin" + "tibet". 

c) For settings, it's "adim" + "000000"

## Finding 3 - CVE-2025-2343: Bypassing of Device Pairing [CWE-798] for IROAD X Series
The IROAD X5 dashcam uses MAC address verification as the sole mechanism for recognizing paired devices, allowing attackers to bypass authentication. By capturing the MAC address of an already-paired device through ARP scanning or other means, an attacker can spoof the MAC address and connect to the dashcam without going through the pairing process. This enables full access to the device.

## Finding 4 - CVE-2025-2344: Remotely Dump Video Footage and Live Video Stream
The IROAD X5 dashcam exposes API endpoints on ports 9091 and 9092 that allow remote access to recorded and live video feeds. An attacker who connects to the dashcam’s network can retrieve all stored recordings and convert them from JDR format to MP4. Additionally, port 9092's RTSP stream can be accessed remotely, allowing real-time video feeds to be extracted without the owner's knowledge. This vulnerability results in severe privacy risks, including exposure of location data embedded in recordings.

## Finding 5 - CVE-2025-2345: Managing Settings to Obtain Sensitive Data and Sabotaging Car Battery
The IROAD X5 dashcam allows unauthorized users to modify critical system settings once connected to its network. Attackers can extract sensitive car and driver information, mute dashcam alerts to prevent detection, disable recording functionality, or even factory reset the device. Additionally, they can disable battery protection, causing the dashcam to drain the car battery when left on overnight. These actions not only compromise privacy but also pose potential physical harm by rendering the dashcam non-functional or causing vehicle battery failure.

![image](https://github.com/user-attachments/assets/0a00b49b-39d3-4163-8e05-9d32b159a34f)


## Finding 6 - CVE-2025-2346: Public Domain Used for Internal Domain Name
The IROAD dashcams uses an unregistered public domain name as internal domain, creating a security risk. During analysis, it was found that this domain was not owned by IROAD, allowing an attacker to register it and potentially intercept sensitive device traffic. If the dashcam or related services attempt to resolve this domain over the internet instead of locally, it could lead to data exfiltration or man-in-the-middle attacks. The vendor has been contacted regarding the potential impact of this issue.

![image](https://github.com/user-attachments/assets/43458854-9dab-432e-8505-ff9cb285d169)


# IROAD FX2

## Finding 7 - CVE-2025-2347: Bypass of Device Pairing/Registration for IROAD FX2
The IROAD FX2 dashcam requires device registration via the "IROAD X View" app for authentication, but its HTTP server lacks this restriction. Once connected to the dashcam’s WiFi using the default password ("qwertyuiop"), an attacker can directly access the HTTP server at http://192.168.10.1 without undergoing the pairing process. Additionally, no alert is triggered on the device when an attacker connects, making this intrusion completely silent.

## Finding 8 - CVE-2025-2348: Dumping Files Over HTTP and RTSP Without Authentication
The IROAD FX2 dashcam lacks authentication controls on its HTTP and RTSP interfaces, allowing attackers to retrieve sensitive files and video recordings. By connecting to http://192.168.10.1/mnt/extsd/event/, an attacker can download all stored video recordings in an unencrypted manner. Additionally, the RTSP stream on port 8554 is accessible without authentication, allowing an attacker to view live footage. The lack of access control poses a serious privacy risk to users.

## Finding 9 - CVE-2025-2349: Exposed Root Password
The IROAD FX2 dashcam stores its root credentials in the /etc/passwd and /etc/shadow files, which can be accessed once an attacker connects to its network and bypasses device registration. By extracting and cracking the password hash, the privileged login root:tina is revealed. Furthermore, the WiFi password is stored in plaintext in configuration files such as hostapd.conf, making it easy for attackers to retrieve and use for persistent unauthorized access.

## Finding 10 - CVE-2025-2350: Unauthenticated Uploads
The IROAD FX2 dashcam exposes an unauthenticated file upload endpoint at http://192.168.10.1/action/upload_file, allowing an attacker to upload arbitrary files to the dashcam’s storage.

## Finding 11 - CVE-2025-30131: Unrestricted Webshell
The IROAD FX2 dashcam’s unauthenticated file upload endpoint can be leveraged to execute arbitrary commands by uploading a CGI-based webshell. Once uploaded, the attacker can execute commands with root privileges, gaining full control over the dashcam. Additionally, by uploading a netcat (nc) binary, the attacker can establish a reverse shell, maintaining persistent remote and privileged access to the device. This critical vulnerability allows for complete device takeover.

![image](https://github.com/user-attachments/assets/f66f572e-1d62-4f66-b5b3-46d1c1611943)

## Finding 12 - CVE-2025-30133: Unprotected URL Shortcut
**Description**: An attacker can either edit the IROAD viewer url on the SD card locally, or edit it remotely via the unauthenticated upload endpoint. The url shortcut file, IROAD_XVIEW_Windows.url, is not write-protected nor access-restricted and can be rewritten to point to an attacker-controlled page to download malware to cause infection, instead of the official dashcam viewer, on the owner's device.

![image](https://github.com/user-attachments/assets/d0d06b20-8f70-4fd1-bae7-ad90734c5496)

**Vulnerability Type**: Incorrect Access Control

**Vendor of Product**: IROAD

**Affected Product Code Base**: IROAD DASHCAM FX2

**Affected Component**: URL Shortcut

**Attack Type**: Remote

**Impact Code execution**: False

**Impact Information Disclosure**: False

**Attack Vectors**: An attacker can remotely change the URL shortcut within the dashcam to redirect dashcam owner to a malware site instead of downloading the legitimate dashcam viewer app on phone.

**Has vendor confirmed or acknowledged the vulnerability?**: No


## Finding 13 - CVE-2025-30133: Locking Owner Out of Device (DoS)
While the IROAD FX2 Dashcam does not allow nor offer a way to change the wifi password, an attacker could change it by downloading the configuration file, ie setup.ini, changing the wifi password, and uploading it to take effect. Because the app does not offer any way to change the password and there are no physical reset buttons, the owner has no way of getting back access to the dashcam. Since the password has been changed, there's no way for the owner to connect back and perform a factory reset as well.

**Vulnerability Type**: Incorrect Access Control

**Vendor of Product**: IROAD

**Affected Product Code Base**: IROAD DASHCAM FX2

**Affected Component**: SSID Password

**Attack Type**: Remote

**Impact Code execution**: False

**Impact Information Disclosure**: False

**Attack Vectors**: An attacker can remotely change the dashcam's SSID password and because dashcam FX2 doesn't have a reset button, the dashcam owner will not be able to connect to the dashcam anymore. 

**Has vendor confirmed or acknowledged the vulnerability?**: No


## Disclosure Timeline

11 Feb 2025 - Disclosed to IROAD

15 Feb 2025 - Follow-up email sent to IROAD

1 Mar 2025 - Final follow-up email sent

14 Mar 2025 - Public disclosure via CVEs
