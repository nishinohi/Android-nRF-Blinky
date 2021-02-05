package no.nordicsemi.android.blinky.profile.packet;

import android.os.Message;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import javax.crypto.SecretKey;

import no.nordicsemi.android.ble.data.DataSplitter;

public class FruityDataSplitter implements DataSplitter {
    private int[] encryptionNonce;
    private SecretKey encryptionKey;

    public FruityDataSplitter(int[] encryptionNonce, SecretKey encryptionKey) {
        if (encryptionNonce != null) {
            this.encryptionNonce = new int[]{encryptionNonce[0], encryptionNonce[1]};
        }
        if (encryptionKey != null) {
            this.encryptionKey = encryptionKey;
        }
    }

    public void setEncryptionKey(SecretKey encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public void setEncryptionNonce(int[] encryptionNonce) {
        this.encryptionNonce = encryptionNonce;
    }

    @Nullable
    @Override
    public byte[] chunk(@NonNull byte[] message, int index, int maxLength) {
        // If packet size is lower than maxLength, you don't have to add split header
        if (index == 0 && FruityPacket.FRUITY_MTU >= message.length + FruityPacket.MESH_ACCESS_MIC_LENGTH) {
            return FruityPacket.encryptPacketWithMIC(message, message.length, encryptionNonce, encryptionKey);
        }

        int maxPayloadSize = FruityPacket.FRUITY_MTU - FruityPacket.MESH_ACCESS_MIC_LENGTH - FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER;
        final int offset = index * maxPayloadSize;
        final int payloadSize = Math.min(maxPayloadSize, message.length - offset);
        if (payloadSize <= 0) return null;
        final int totalPayloadSize = payloadSize + FruityPacket.MESH_ACCESS_MIC_LENGTH + FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER;
        final int payloadSizeWithSplitHeader = payloadSize + FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER;

        final byte[] nonEncryptData = new byte[payloadSizeWithSplitHeader];
        // MessageType changes when you send last packet
        nonEncryptData[0] = maxPayloadSize >= message.length - offset ?
                FruityPacket.MessageType.SPLIT_WRITE_CMD_END.getTypeValue() : FruityPacket.MessageType.SPLIT_WRITE_CMD.getTypeValue();
        nonEncryptData[1] = (byte) index;
        System.arraycopy(message, offset, nonEncryptData, FruityPacket.PacketSplitHeader.SIZEOF_CONN_PACKET_SPLIT_HEADER, payloadSize);
        return FruityPacket.encryptPacketWithMIC(nonEncryptData, nonEncryptData.length, encryptionNonce, encryptionKey);
    }
}
