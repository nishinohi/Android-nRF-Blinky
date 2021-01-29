package no.nordicsemi.android.blinky.profile.callback;

import android.bluetooth.BluetoothDevice;
import android.util.Log;

import androidx.annotation.NonNull;

import no.nordicsemi.android.ble.callback.profile.ProfileDataCallback;
import no.nordicsemi.android.ble.data.Data;

public class FruityEncryptDataCallback implements ProfileDataCallback, FruityEncryptCallback {
    @Override
    public void onDataReceived(@NonNull BluetoothDevice device, @NonNull Data data) {
        Log.d("FM", "onDataReceived: " + data);
    }

    @Override
    public void onEncryptStageChanged(@NonNull BluetoothDevice device, boolean on) {

    }

}
