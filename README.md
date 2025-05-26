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
3. Or install manually through file manager

### Step 2: LSPosed Configuration
1. Open **LSPosed Manager**
2. Go to **Modules** tab
3. Enable **SIM Spoof Module**
4. Configure scope (see Scope Configuration below)
5. **Reboot** your device

### Step 3: Scope Configuration
The module follows Hide-My-Applist's approach by hooking **ONLY** the System Framework:

**Required Scope:**
- ✅ **System Framework** (`android`) - **ONLY** scope needed

**Why Only System Framework?**
- 🎯 **Universal Coverage**: All app requests go through Android framework
- 🔒 **Better Stealth**: No individual app hooks = harder to detect
- ⚡ **Better Performance**: Single hook point instead of multiple apps
- 🛡️ **Framework-level Protection**: Intercepts calls before they reach apps

**No Individual App Selection Needed!** The system framework hooks automatically protect all apps on your device.

### Step 4: Verification
1. Check LSPosed logs for activation confirmation
2. Use apps that previously detected your environment
3. Monitor logs for interception messages

## ⚙️ Configuration

### SIM Spoofing Values
Edit the following constants in the source code before building:

```java
// === SIM Card Information ===
private static final String SPOOFED_ICCID = "89860123456789012345";  // 19-20 digits
private static final String SPOOFED_IMSI = "310260123456789";         // 15 digits

// === Phone Number Information ===
private static final String SPOOFED_PHONE_NUMBER = "+1234567890";     // International format
private static final String SPOOFED_LINE1_NUMBER = "1234567890";      // Local format
private static final String SPOOFED_SUBSCRIBER_NUMBER = "1234567890";
private static final String SPOOFED_VOICE_MAIL_NUMBER = "123";

// === Country and Network Information ===
private static final String SPOOFED_COUNTRY_ISO = "US";               // 2-letter country code
private static final String SPOOFED_NETWORK_COUNTRY_ISO = "US";
private static final String SPOOFED_SIM_COUNTRY_ISO = "US";
private static final String SPOOFED_NETWORK_OPERATOR = "310260";      // MCC+MNC (T-Mobile US)
private static final String SPOOFED_NETWORK_OPERATOR_NAME = "T-Mobile";
private static final String SPOOFED_SIM_OPERATOR = "310260";
private static final String SPOOFED_SIM_OPERATOR_NAME = "T-Mobile";

// === Device Information ===
private static final String SPOOFED_DEVICE_ID = "123456789012345";    // IMEI (15 digits)
private static final String SPOOFED_DEVICE_SOFTWARE_VERSION = "01";
private static final String SPOOFED_GROUP_ID_LEVEL1 = "0";
```

### Common Country/Operator Combinations:

| Country | ISO | MCC+MNC | Operator | Example IMSI |
|---------|-----|---------|----------|--------------|
| United States | US | 310260 | T-Mobile | 310260123456789 |
| United States | US | 310410 | AT&T | 310410123456789 |
| United Kingdom | GB | 23415 | Vodafone | 234151234567890 |
| Germany | DE | 26202 | Vodafone | 262021234567890 |
| France | FR | 20801 | Orange | 208011234567890 |
| Canada | CA | 30272 | Rogers | 302721234567890 |

### Target Apps
**No manual app targeting needed!** The module hooks only the system framework, which automatically covers all apps. Simply modify the ICCID/IMSI values:

```java
// Customize these values
private static final String SPOOFED_ICCID = "89860123456789012345";
private static final String SPOOFED_IMSI = "310260123456789";
```

### Detection Strings
Customize detection strings to block:

```java
private static final String[] DETECTION_STRINGS = {
    "xposed", "lsposed", "edxposed",
    "custom_detection_string"  // Add custom strings
};
```

## 🛠️ Building from Source

### Prerequisites
- Android Studio 4.0+
- Android SDK with API 34+
- Java 8+

### Build Steps
```bash
git clone https://github.com/yourusername/sim-spoof-module
cd sim-spoof-module
./gradlew assembleRelease
```

The APK will be generated in `app/build/outputs/apk/release/`

## 📱 Scope Configuration Guide

### System Framework (Only Required Scope)
- **Package**: `android`
- **Purpose**: Universal coverage for all apps
- **Why this approach**: 
  - 🎯 **Single point of control**: All API calls go through framework
  - 🔒 **Maximum stealth**: No individual app hooks to detect
  - ⚡ **Best performance**: One hook instead of many
  - 🛡️ **Comprehensive protection**: Covers all apps automatically

### Why Not Individual Apps?
Unlike other modules, this follows Hide-My-Applist's proven approach:
- ❌ **No individual app selection needed**
- ❌ **No performance impact from multiple hooks** 
- ❌ **No detection risk from app-specific hooks**
- ✅ **Universal protection for ALL apps**

## 🔍 How It Works

### SIM Spoofing Mechanism
1. **TelephonyManager Hooks**: Intercepts `getSimSerialNumber()` and `getSubscriberId()`
2. **SubscriptionManager Hooks**: Blocks `getActiveSubscriptionInfoList()`
3. **SubscriptionInfo Hooks**: Replaces `getIccId()` calls
4. **Multi-API Support**: Handles different Android versions

### Anti-Detection Framework
1. **String Interception**: Hooks `String.equals()`, `String.contains()`, `TextUtils.equals()`
2. **File System Hooks**: Intercepts `File.exists()`, `File.listFiles()`, `BufferedReader.readLine()`
3. **Process Filtering**: Filters `Runtime.exec()`, `ProcessBuilder.start()`, process output
4. **System Integration**: Hooks PackageManagerService for app list filtering

### Stealth Techniques
Inspired by Hide-My-Applist methodology:
- **Framework-level hooks** for maximum coverage
- **Selective targeting** for performance optimization  
- **Multi-layer protection** against various detection methods
- **Dynamic filtering** of detection strings and paths

## 🐛 Troubleshooting

### Module Not Working
- ✅ Verify LSPosed is installed and working
- ✅ Check module is enabled in LSPosed Manager
- ✅ Ensure correct scope configuration (System Framework + Target Apps)
- ✅ Reboot device after enabling
- ✅ Check LSPosed logs for errors

### Apps Still Detecting
- 📝 Add more detection strings to the filter list
- 📝 Verify target app is in the scope
- 📝 Check if app uses native detection methods
- 📝 Consider additional Magisk Hide modules

### Performance Issues
- ⚡ Reduce number of target apps in scope
- ⚡ Disable verbose logging
- ⚡ Check for conflicts with other modules

### Boot Loops
- 🔄 Boot to recovery mode
- 🔄 Disable the module in LSPosed
- 🔄 Check compatibility with your Android version

## 📊 Detection Methods Blocked

| Detection Type | Method | Status |
|----------------|--------|--------|
| **SIM Information** | TelephonyManager.getSimSerialNumber() | ✅ Blocked |
| **IMSI** | TelephonyManager.getSubscriberId() | ✅ Blocked |
| **Phone Number** | TelephonyManager.getLine1Number() | ✅ Blocked |
| **Country Code** | TelephonyManager.getSimCountryIso() | ✅ Blocked |
| **Network Operator** | TelephonyManager.getNetworkOperator() | ✅ Blocked |
| **Carrier Name** | TelephonyManager.getNetworkOperatorName() | ✅ Blocked |
| **Device ID (IMEI)** | TelephonyManager.getDeviceId() | ✅ Blocked |
| **Subscription Info** | SubscriptionManager APIs | ✅ Blocked |
| **Multi-SIM Methods** | All subscription-based methods | ✅ Blocked |
| String Comparison | equals(), contains() | ✅ Blocked |
| File Existence | File.exists() | ✅ Blocked |
| Directory Listing | File.listFiles() | ✅ Blocked |
| Process Execution | Runtime.exec() | ✅ Blocked |
| Memory Maps | /proc/self/maps | ✅ Filtered |
| Package Lists | PackageManager | ✅ Filtered |
| Thread Names | Thread.getName() | ✅ Masked |
| Debug Detection | Debug.isDebuggerConnected() | ✅ Blocked |

## 🔐 Security Considerations

### Privacy
- Module only hooks specified target applications
- No network communication or data collection
- All processing happens locally on device

### Safety
- Extensive error handling to prevent crashes
- Selective scope to minimize system impact
- Compatible with safety-critical system functions

### Detection Resistance
- Uses proven Hide-My-Applist techniques
- Multi-layer protection approach
- Regular updates for new detection methods

## 🤝 Contributing

We welcome contributions! Please read our contributing guidelines:

1. **Fork** the repository
2. **Create** a feature branch
3. **Test** thoroughly on multiple devices
4. **Submit** a pull request with detailed description

### Areas for Contribution
- Additional SIM-related API hooks
- New detection string discoveries
- Android version compatibility
- Performance optimizations
- Documentation improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Notice

This software is provided for educational and research purposes only. Users must:
- Comply with all applicable laws and regulations
- Respect terms of service of applications
- Use responsibly and ethically
- Not use for malicious purposes

The developers disclaim any responsibility for misuse or legal consequences.

## 🙏 Acknowledgments

- **Dr-TSNG** for Hide-My-Applist inspiration and techniques
- **LSPosed Team** for the excellent framework
- **Xposed Community** for continued development and support
- **Android Security Researchers** for detection method discoveries

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/sim-spoof-module/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/sim-spoof-module/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/sim-spoof-module/wiki)

---

**⭐ If this module helped you, please consider giving it a star!**

**🔄 Stay updated by watching the repository for new releases and security updates.**
