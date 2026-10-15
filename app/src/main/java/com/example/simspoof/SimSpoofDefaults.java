package com.example.simspoof;

/** Fallback values used when no settings have been saved yet. */
final class SimSpoofDefaults {
    static final String ICCID = "89860123456789012345";
    static final String IMSI = "310260123456789";
    static final String PHONE_NUMBER = "1234567890";
    static final String SUBSCRIBER_NUMBER = "1234567890";
    static final String VOICE_MAIL_NUMBER = "123";
    static final String COUNTRY_ISO = "US";
    static final String NETWORK_OPERATOR = "310260"; // MCC+MNC, T-Mobile US
    static final String OPERATOR_NAME = "T-Mobile";
    static final String DEVICE_ID = "123456789012345"; // IMEI
    static final String DEVICE_SOFTWARE_VERSION = "01";
    static final String GROUP_ID_LEVEL1 = "0";

    private SimSpoofDefaults() {
    }
}
