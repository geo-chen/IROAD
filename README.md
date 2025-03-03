# IROAD X Series

Product: https://www.iroadau.com.au

## Finding 1: Default credentials for SSID [CWE-1393]
The IROAD X5 dashcam broadcasts a fixed SSID with default credentials that cannot be changed. This allows any nearby attacker to connect to the dashcam’s network without restriction. Once connected, an attacker can sniff on connected devices such as the user’s smartphone. The SSID is also always broadcasted.

## Finding 2: Hardcoded credentials in APK (IROAD <= v5.2.5) to ports 9091 and 9092
The IROAD X5 mobile application (version 5.2.5 and below) contains hardcoded credentials that provide unauthorized access to the dashcam's API endpoints on ports 9091 and 9092:

a) Once IRoad SSID is connected to, the attacker sends a crafted authentication command with "TibetList" and "000000" to list settings of the dashcam at port 9091. 

b) There's a separate set of credentials for port 9092 (stream) that is exposed in plaintext as well, "admin" + "tibet". 

c) For settings, it's "adim" + "000000"

## Finding 3: Bypassing of Device Pairing [CWE-798] for IROAD X Series
The IROAD X5 dashcam uses MAC address verification as the sole mechanism for recognizing paired devices, allowing attackers to bypass authentication. By capturing the MAC address of an already-paired device through ARP scanning or other means, an attacker can spoof the MAC address and connect to the dashcam without going through the pairing process. This enables full access to the device.

## Finding 4: Remotely Dump Video Footage and Live Video Stream
The IROAD X5 dashcam exposes API endpoints on ports 9091 and 9092 that allow remote access to recorded and live video feeds. An attacker who connects to the dashcam’s network can retrieve all stored recordings and convert them from JDR format to MP4. Additionally, port 9092's RTSP stream can be accessed remotely, allowing real-time video feeds to be extracted without the owner's knowledge. This vulnerability results in severe privacy risks, including exposure of location data embedded in recordings.

## Finding 5: Managing Settings to Obtain Sensitive Data and Sabotaging Car Battery
The IROAD X5 dashcam allows unauthorized users to modify critical system settings once connected to its network. Attackers can extract sensitive car and driver information, mute dashcam alerts to prevent detection, disable recording functionality, or even factory reset the device. Additionally, they can disable battery protection, causing the dashcam to drain the car battery when left on overnight. These actions not only compromise privacy but also pose potential physical harm by rendering the dashcam non-functional or causing vehicle battery failure.

## Finding 6: Public Domain Used for Internal Domain Name
The IROAD dashcams uses an unregistered public domain name as internal domain, creating a security risk. During analysis, it was found that this domain was not owned by IROAD, allowing an attacker to register it and potentially intercept sensitive device traffic. If the dashcam or related services attempt to resolve this domain over the internet instead of locally, it could lead to data exfiltration or man-in-the-middle attacks. The vendor has been contacted regarding the potential impact of this issue.

![image](https://github.com/user-attachments/assets/43458854-9dab-432e-8505-ff9cb285d169)


# IROAD FX2

## Finding 7: Bypass of Device Pairing/Registration for IROAD FX2
The IROAD FX2 dashcam requires device registration via the "IROAD X View" app for authentication, but its HTTP server lacks this restriction. Once connected to the dashcam’s WiFi using the default password ("qwertyuiop"), an attacker can directly access the HTTP server at http://192.168.10.1 without undergoing the pairing process. Additionally, no alert is triggered on the device when an attacker connects, making this intrusion completely silent.

## Finding 8: Dumping Files Over HTTP and RTSP Without Authentication
The IROAD FX2 dashcam lacks authentication controls on its HTTP and RTSP interfaces, allowing attackers to retrieve sensitive files and video recordings. By connecting to http://192.168.10.1/mnt/extsd/event/, an attacker can download all stored video recordings in an unencrypted manner. Additionally, the RTSP stream on port 8554 is accessible without authentication, allowing an attacker to view live footage. The lack of access control poses a serious privacy risk to users.

## Finding 9: Exposed Root Password
The IROAD FX2 dashcam stores its root credentials in the /etc/passwd and /etc/shadow files, which can be accessed once an attacker connects to its network and bypasses device registration. By extracting and cracking the password hash, the privileged login root:tina is revealed. Furthermore, the WiFi password is stored in plaintext in configuration files such as hostapd.conf, making it easy for attackers to retrieve and use for persistent unauthorized access.

## Finding 10: Unauthenticated Uploads
The IROAD FX2 dashcam exposes an unauthenticated file upload endpoint at http://192.168.10.1/action/upload_file, allowing an attacker to upload arbitrary files to the dashcam’s storage. This can be exploited to overwrite critical configuration files, such as setup.ini, changing the SSID password and locking the original user out of their device. Attackers can also replace IROAD_XVIEW_Windows.url with a malicious link to trick users into downloading malware onto their devices.

![image](https://github.com/user-attachments/assets/d0d06b20-8f70-4fd1-bae7-ad90734c5496)


## Finding 11: Unrestricted Webshell
The IROAD FX2 dashcam’s unauthenticated file upload endpoint can be leveraged to execute arbitrary commands by uploading a CGI-based webshell. Once uploaded, the attacker can execute commands with root privileges, gaining full control over the dashcam. Additionally, by uploading a netcat (nc) binary, the attacker can establish a reverse shell, maintaining persistent remote and privileged access to the device. This critical vulnerability allows for complete device takeover.

![image](https://github.com/user-attachments/assets/f66f572e-1d62-4f66-b5b3-46d1c1611943)


