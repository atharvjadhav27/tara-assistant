# TCU-Gen2 System Architecture (SAMPLE - anonymised, illustrative)

Document: TCU-Gen2 Architecture Description, version 0.9, review date 2026-06-30

## 1. System overview

The Telematics Control Unit (TCU-Gen2) is a connected gateway ECU. It hosts an application processor running a hardened Linux image, a 4G/5G cellular modem, a Hardware Security Module (HSM) with secure boot, and a vehicle gateway function. The TCU connects to the vehicle through Powertrain CAN, Body CAN, 100BASE-T1 automotive Ethernet and an OBD-II diagnostic connector, and to the OEM cloud backend through the cellular modem.

## 2. Interface: CAN

The TCU gateway is attached to Powertrain CAN (500 kbit/s) and Body CAN (500 kbit/s). Vehicle speed, torque request, door-lock status and gateway routing messages are exchanged as CAN signals. Powertrain messages are protected by SecOC freshness and MAC on safety-relevant frames; Body CAN messages are currently unauthenticated. The gateway forwards a restricted allow-list of messages between Body CAN and Powertrain CAN.

## 3. Interface: Ethernet

A 100BASE-T1 link connects the TCU to the infotainment head unit and the ADAS domain controller through an automotive Ethernet switch. Service-oriented communication uses SOME/IP over VLAN-segregated networks. Port authentication and traffic encryption (MACsec) are planned but not yet enabled in the sample build.

## 4. Interface: Diagnostics

The OBD-II connector exposes diagnostic communication to the TCU: UDS over CAN and UDS over DoIP. Diagnostic services include session control, security access, read data by identifier and request download (flash programming). Security access uses a seed-and-key mechanism; session timeouts are configurable.

## 5. Interface: OTA

The TCU hosts the OTA update client. The client polls the OEM update server over TLS, downloads the update manifest and the signed update package, verifies the package, and installs it into an inactive firmware partition (A/B scheme) before activation after reboot. The manifest contains the target version and version counter.

## 6. Interface: Backend

The cellular modem provides a TLS 1.2 connection to the OEM cloud backend for telematics data upload, remote commands (remote lock, remote climate) and OTA control messages. Device credentials (X.509 client certificate and private key) are stored in the HSM. Telematics data includes location history, trip data and diagnostic trouble codes and is personal data.

## 7. Hardware security and debug

The HSM stores device private keys and the firmware verification root key. Secure boot verifies the bootloader and the application image. JTAG and UART debug ports exist on the development board; production lock-down of these ports is under review.

## 8. Trust boundaries

- Boundary TB-1: cellular network and OEM backend versus the TCU modem.
- Boundary TB-2: OBD-II connector (external physical access) versus the TCU diagnostic stack.
- Boundary TB-3: Body CAN and infotainment/ADAS Ethernet domains versus the Powertrain CAN domain at the gateway.
- Boundary TB-4: TCU application processor versus the HSM secure environment.
