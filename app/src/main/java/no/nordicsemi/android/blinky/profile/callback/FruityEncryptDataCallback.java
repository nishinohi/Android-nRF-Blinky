package no.nordicsemi.android.blinky.profile.callback;

import android.bluetooth.BluetoothDevice;
import android.util.Log;

import androidx.annotation.NonNull;

import no.nordicsemi.android.ble.callback.DataSentCallback;
import no.nordicsemi.android.ble.callback.profile.ProfileDataCallback;
import no.nordicsemi.android.ble.data.Data;
import no.nordicsemi.android.blinky.profile.packet.FruityPacket;

public abstract class FruityEncryptDataCallback implements ProfileDataCallback, FruityEncryptCallback, DataSentCallback {
    @Override
    public void onEncryptStageChanged(@NonNull BluetoothDevice device, boolean on) {
    }

    public void parsePacket(Data packetData) {
        byte packet[] = packetData.getValue();
        final int a = FruityPacket.MessageType.ENCRYPT_CUSTOM_ANONCE.getTypeValue();
        FruityPacket.MessageType messageType = FruityPacket.MessageType.getTypeEnum(packet[0]);
        switch (messageType) {
            case ENCRYPT_CUSTOM_ANONCE:
                onANonceReceived(packetData);
                break;
            default:
                Log.d("FM", "Unknown MessageType: " + messageType);
//                throw new IllegalStateException("Unexpected value: " + messageType);
        }
    }

}
