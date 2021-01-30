package no.nordicsemi.android.blinky.profile.callback;

import android.bluetooth.BluetoothDevice;

import androidx.annotation.NonNull;

import no.nordicsemi.android.ble.data.Data;

public interface FruityEncryptCallback {
    void onANonceReceived(@NonNull Data customANoncePacket);
    void onEncryptStageChanged(@NonNull final BluetoothDevice device, final boolean on);
}
