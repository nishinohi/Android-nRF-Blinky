package no.nordicsemi.android.blinky.profile.callback;

import android.bluetooth.BluetoothDevice;

import androidx.annotation.NonNull;

public interface FruityEncryptCallback {
    void onEncryptStageChanged(@NonNull final BluetoothDevice device, final boolean on);
}
