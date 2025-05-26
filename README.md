# SIM Spoof LSPosed Module

An advanced LSPosed/Xposed module for spoofing SIM card information (ICCID, IMSI) and providing comprehensive anti-detection capabilities. This module combines SIM spoofing functionality with proven stealth techniques inspired by Hide-My-Applist.

## ⚠️ Disclaimer

This module is for educational and research purposes only. Users are responsible for compliance with local laws and terms of service of applications they use. The developers are not responsible for any misuse or consequences.

## 🚀 Features

### SIM Card Spoofing
- **ICCID Spoofing**: Replace SIM serial number with custom values
- **IMSI Spoofing**: Modify subscriber ID (IMSI)
- **Phone Number Spoofing**: Change Line1 number and subscriber number
- **Country Information**: Spoof country ISO codes and network operators
- **Carrier Information**: Modify network operator names and codes
- **Device ID Spoofing**: Replace IMEI and device identifiers
- **Multi-SIM Support**: Compatible with dual-SIM devices
- **Subscription Manager**: Hook subscription-related APIs
- **Comprehensive Coverage**: All TelephonyManager methods hooked

### Advanced Anti-Detection
- **System Framework Hooks**: Deep integration at Android framework level
- **String Comparison Bypass**: Intercept and block detection string comparisons
- **File System Protection**: Hide sensitive files and paths from detection
- **Process Output Filtering**: Filter detection strings from process outputs
- **Root Detection Bypass**: Block common root detection methods
- **Debugger Detection Bypass**: Hide debugging connections

### Stealth Technologies
- **LSPosed/Xposed Hiding**: Comprehensive protection against framework detection
- **Thread Name Masking**: Hide suspicious thread names
- **/proc/maps Filtering**: Remove module traces from memory maps
- **Package List Filtering**: Hide sensitive packages from system queries
- **Directory Hiding**: Filter file listings to remove traces

## 📋 Requirements

- **Root Access**: Device must be rooted
- **LSPosed Framework**: LSPosed v1.8.0+ or compatible Xposed framework
- **Android Version**: Android 7.0+ (API 24+)
- **Architecture**: ARM64 or ARM32

## 🔧 Installation

### Step 1: Download and Install
1. Download the latest APK from releases
2. Install the APK: `adb install SimSpoofModule.apk`
