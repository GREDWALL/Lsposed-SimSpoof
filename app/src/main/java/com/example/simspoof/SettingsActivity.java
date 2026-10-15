package com.example.simspoof;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.File;

import static com.example.simspoof.SimSpoofConstants.KEY_COUNTRY_ISO;
import static com.example.simspoof.SimSpoofConstants.KEY_DEVICE_ID;
import static com.example.simspoof.SimSpoofConstants.KEY_DEVICE_SOFTWARE_VERSION;
import static com.example.simspoof.SimSpoofConstants.KEY_GROUP_ID_LEVEL1;
import static com.example.simspoof.SimSpoofConstants.KEY_ICCID;
import static com.example.simspoof.SimSpoofConstants.KEY_IMSI;
import static com.example.simspoof.SimSpoofConstants.KEY_NETWORK_OPERATOR;
import static com.example.simspoof.SimSpoofConstants.KEY_OPERATOR_NAME;
import static com.example.simspoof.SimSpoofConstants.KEY_PHONE_NUMBER;
import static com.example.simspoof.SimSpoofConstants.KEY_SUBSCRIBER_NUMBER;
import static com.example.simspoof.SimSpoofConstants.KEY_VOICE_MAIL_NUMBER;
import static com.example.simspoof.SimSpoofConstants.PREFS_NAME;

/**
 * Lets the user edit the spoofed SIM/device values without rebuilding the APK.
 * Values are stored in a SharedPreferences file that the hooked system process
 * reads back via {@link de.robv.android.xposed.XSharedPreferences}, which is why
 * the file is made world-readable after every write (XSharedPreferences reads it
 * directly off disk, not through this app's process).
 */
public class SettingsActivity extends Activity {

    private EditText editIccid;
    private EditText editImsi;
    private EditText editPhoneNumber;
    private EditText editSubscriberNumber;
    private EditText editVoiceMailNumber;
    private EditText editCountryIso;
    private EditText editNetworkOperator;
    private EditText editOperatorName;
    private EditText editDeviceId;
    private EditText editDeviceSoftwareVersion;
    private EditText editGroupIdLevel1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        editIccid = findViewById(R.id.edit_iccid);
        editImsi = findViewById(R.id.edit_imsi);
        editPhoneNumber = findViewById(R.id.edit_phone_number);
        editSubscriberNumber = findViewById(R.id.edit_subscriber_number);
        editVoiceMailNumber = findViewById(R.id.edit_voice_mail_number);
        editCountryIso = findViewById(R.id.edit_country_iso);
        editNetworkOperator = findViewById(R.id.edit_network_operator);
        editOperatorName = findViewById(R.id.edit_operator_name);
        editDeviceId = findViewById(R.id.edit_device_id);
        editDeviceSoftwareVersion = findViewById(R.id.edit_device_software_version);
        editGroupIdLevel1 = findViewById(R.id.edit_group_id_level1);

        loadIntoFields();

        Button buttonSave = findViewById(R.id.button_save);
        buttonSave.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                saveFields();
            }
        });

        Button buttonReset = findViewById(R.id.button_reset);
        buttonReset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                resetToDefaults();
            }
        });
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
    }

    private void loadIntoFields() {
        SharedPreferences prefs = prefs();
        editIccid.setText(prefs.getString(KEY_ICCID, SimSpoofDefaults.ICCID));
        editImsi.setText(prefs.getString(KEY_IMSI, SimSpoofDefaults.IMSI));
        editPhoneNumber.setText(prefs.getString(KEY_PHONE_NUMBER, SimSpoofDefaults.PHONE_NUMBER));
        editSubscriberNumber.setText(prefs.getString(KEY_SUBSCRIBER_NUMBER, SimSpoofDefaults.SUBSCRIBER_NUMBER));
        editVoiceMailNumber.setText(prefs.getString(KEY_VOICE_MAIL_NUMBER, SimSpoofDefaults.VOICE_MAIL_NUMBER));
        editCountryIso.setText(prefs.getString(KEY_COUNTRY_ISO, SimSpoofDefaults.COUNTRY_ISO));
        editNetworkOperator.setText(prefs.getString(KEY_NETWORK_OPERATOR, SimSpoofDefaults.NETWORK_OPERATOR));
        editOperatorName.setText(prefs.getString(KEY_OPERATOR_NAME, SimSpoofDefaults.OPERATOR_NAME));
        editDeviceId.setText(prefs.getString(KEY_DEVICE_ID, SimSpoofDefaults.DEVICE_ID));
        editDeviceSoftwareVersion.setText(prefs.getString(KEY_DEVICE_SOFTWARE_VERSION, SimSpoofDefaults.DEVICE_SOFTWARE_VERSION));
        editGroupIdLevel1.setText(prefs.getString(KEY_GROUP_ID_LEVEL1, SimSpoofDefaults.GROUP_ID_LEVEL1));
    }

    private void saveFields() {
        prefs().edit()
                .putString(KEY_ICCID, editIccid.getText().toString().trim())
                .putString(KEY_IMSI, editImsi.getText().toString().trim())
                .putString(KEY_PHONE_NUMBER, editPhoneNumber.getText().toString().trim())
                .putString(KEY_SUBSCRIBER_NUMBER, editSubscriberNumber.getText().toString().trim())
                .putString(KEY_VOICE_MAIL_NUMBER, editVoiceMailNumber.getText().toString().trim())
                .putString(KEY_COUNTRY_ISO, editCountryIso.getText().toString().trim())
                .putString(KEY_NETWORK_OPERATOR, editNetworkOperator.getText().toString().trim())
                .putString(KEY_OPERATOR_NAME, editOperatorName.getText().toString().trim())
                .putString(KEY_DEVICE_ID, editDeviceId.getText().toString().trim())
                .putString(KEY_DEVICE_SOFTWARE_VERSION, editDeviceSoftwareVersion.getText().toString().trim())
                .putString(KEY_GROUP_ID_LEVEL1, editGroupIdLevel1.getText().toString().trim())
                .commit(); // commit (not apply): must finish before we chmod the file below

        makePrefsFileWorldReadable();
        Toast.makeText(this, R.string.toast_saved, Toast.LENGTH_LONG).show();
    }

    private void resetToDefaults() {
        prefs().edit().clear().commit();
        makePrefsFileWorldReadable();
        loadIntoFields();
        Toast.makeText(this, R.string.toast_reset, Toast.LENGTH_SHORT).show();
    }

    /**
     * XSharedPreferences reads this file straight off disk from the system process,
     * which has no access grant to this app's private storage otherwise.
     */
    private void makePrefsFileWorldReadable() {
        File prefsDir = new File(getApplicationInfo().dataDir, "shared_prefs");
        prefsDir.setExecutable(true, false);
        prefsDir.setReadable(true, false);
        File prefsFile = new File(prefsDir, PREFS_NAME + ".xml");
        if (prefsFile.exists()) {
            prefsFile.setReadable(true, false);
        }
    }
}
