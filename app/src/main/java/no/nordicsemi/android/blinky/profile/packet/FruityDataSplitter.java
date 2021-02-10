package no.nordicsemi.android.blinky.profile.packet;

import android.os.Message;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import javax.crypto.SecretKey;

import no.nordicsemi.android.ble.data.DataSplitter;

public class FruityDataSplitter implements DataSplitter {
    private int[] encryptionNonce = null;
    private SecretKey encryptionKey = null;

    public FruityDataSplitter(int[] encryptionNonce, SecretKey encryptionKey) {
        if (encryptionNonce != null) {
            this.encryptionNonce = encryptionNonce;
        }
        if (encryptionKey != null) {
            this.encryptionKey = encryptionKey;
        }
    }

    // true : encrypted
    public boolean isEncrypted() {
        return this.encryptionNonce != null && this.encryptionKey != null;
    }

    @Nullable
    @Override
    public byte[] chunk(@NonNull byte[] message, int index, int maxLength) {
        // If packet size is lower than maxLength, you don't have to add split header
        if (index == 0 && FruityPacket.FRUITY_MTU >= message.length + FruityPacket.MESH_ACCESS_MIC_LENGTH) {
            if (!isEncrypted()) return message;
            byte[] encryptedPacket = FruityPacket.encryptPacketWithMIC(message, message.length, encryptionNonce, encryptionKey);
            encryptionNonce[1] += 2;
            return encryptedPacket;
        }

        int maxPayloadSize = isEncrypted() ?
                FruityPacket.FRUITY_MTU - FruityPacket.MESH_ACCESS_MIC_LENGTH - FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER :
                FruityPacket.FRUITY_MTU - FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER;
        final int offset = index * maxPayloadSize;
        final int payloadSize = Math.min(maxPayloadSize, message.length - offset);
        if (payloadSize <= 0) return null;
        final int payloadSizeWithSplitHeader = payloadSize + FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER;

        final byte[] nonEncryptedData = new byte[payloadSizeWithSplitHeader];
        // MessageType changes when you send last packet
        nonEncryptedData[0] = maxPayloadSize >= message.length - offset ?
                FruityPacket.MessageType.SPLIT_WRITE_CMD_END.getTypeValue() : FruityPacket.MessageType.SPLIT_WRITE_CMD.getTypeValue();
        nonEncryptedData[1] = (byte) index;
        System.arraycopy(message, offset, nonEncryptedData, FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER, payloadSize);
        if (!isEncrypted()) return nonEncryptedData;
        byte[] encryptedPacket = FruityPacket.encryptPacketWithMIC(nonEncryptedData, nonEncryptedData.length, encryptionNonce, encryptionKey);
        encryptionNonce[1] += 2; // increment
        return encryptedPacket;
    }
}
