package no.nordicsemi.android.blinky.profile.callback;

import android.bluetooth.BluetoothDevice;
import android.util.Log;

import androidx.annotation.NonNull;

import no.nordicsemi.android.ble.callback.profile.ProfileDataCallback;
import no.nordicsemi.android.ble.data.Data;
import no.nordicsemi.android.blinky.profile.packet.FruityPacket;

public abstract class FruityEncryptDataCallback implements ProfileDataCallback, FruityEncryptCallback {
    @Override
    public void onDataReceived(@NonNull BluetoothDevice device, @NonNull Data packet) {
        Log.d("FM", "onDataReceived: " + packet);
        parsePacket(packet);
    }

    @Override
    public void onEncryptStageChanged(@NonNull BluetoothDevice device, boolean on) {
    }

    private void parsePacket(Data packetData) {
        byte packet[] = packetData.getValue();
        final int a = FruityPacket.MessageType.ENCRYPT_CUSTOM_ANONCE.getTypeValue();
        FruityPacket.MessageType messageType = FruityPacket.MessageType.getTypeEnum((int)packet[0]);
        switch (messageType) {
            case ENCRYPT_CUSTOM_ANONCE:
                onANonceReceived(packetData);
                break;
            default:
//                throw new IllegalStateException("Unexpected value: " + messageType);
        }
    }

}
