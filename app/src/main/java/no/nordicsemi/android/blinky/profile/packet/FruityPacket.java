package no.nordicsemi.android.blinky.profile.packet;


import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import no.nordicsemi.android.ble.data.Data;

public class FruityPacket {
    private static final int nodeId = 631;

    public static byte[] createEncryptCustomStartPacket(ConnPacketEncryptCustomStart packet) {
        byte convertPacket[] = new byte[11];
        convertPacket[0] = (byte) packet.header.messageType.getType();
        byte[] temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.header.sender).array();
        convertPacket[1] = temp[0];
        convertPacket[2] = temp[1];
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.header.receiver).array();
        convertPacket[3] = temp[0];
        convertPacket[4] = temp[1];
        convertPacket[5] = (byte) packet.version;
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.fmKeyId.getKeyId()).array();
        convertPacket[6] = temp[0];
        convertPacket[7] = temp[1];
        convertPacket[8] = temp[2];
        convertPacket[9] = temp[3];
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.reserved).array();
        convertPacket[10] = temp[0];
        convertPacket[10] = (byte) (convertPacket[10] << 2);
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.tunnelType).array();
        convertPacket[10] = (byte) (convertPacket[10] | temp[0]);
        return convertPacket;
    }

    public static int[] readEncryptCustomANonce(Data aNonoce) {
        byte customANoncePacket[] = aNonoce.getValue();
        int aNonceFirst = ByteBuffer.wrap(customANoncePacket, 5, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int aNonceSecond = ByteBuffer.wrap(customANoncePacket, 9, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return new int[]{aNonceFirst, aNonceSecond};
    }

    public static byte[] createANoncePlainText() {
        byte plainText[] = new byte[16];
        byte[] temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(nodeId).array();
        System.arraycopy(temp, 0, plainText, 0, 2);

        return plainText;
    }

    public static byte[] encryptAES128(byte[] plainText, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        Cipher cipherNoPad = Cipher.getInstance("AES_128/ECB/NoPadding");
        cipherNoPad.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipNoPadText = cipherNoPad.doFinal(plainText);
        return cipNoPadText;
    }

    public static final class ConnPacketEncryptCustomStart {
        public ConnPacketHeader header = new ConnPacketHeader();
        public int version;
        public FmKeyId fmKeyId;
        public int tunnelType;
        public int reserved;

        final static int SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_START = 13;
    }

    public static final class ConnPacketHeader {
        public MessageType messageType;
        public int sender;
        public int receiver;
    }

    public static final class BaseConnectionSendData {
        public int characteristicHandle;
        public DeliveryOption deliveryOption;
        public int dataLength;
    }

    public enum MessageType {
        INVALID(0),
        SPLIT_WRITE_CMD(16), //Used if a WRITE_CMD message is split
        SPLIT_WRITE_CMD_END(17), //Used if a WRITE_CMD message is split
        CLUSTER_WELCOME(20), //The initial message after a connection setup (Sent between two nodes)
        CLUSTER_ACK_1(21), //Both sides must acknowledge the handshake (Sent between two nodes)
        CLUSTER_ACK_2(22), //Second ack (Sent between two nodes)
        CLUSTER_INFO_UPDATE(23), //When the cluster size changes), this message is used (Sent to all nodes)
        RECONNECT(24), //Sent while trying to reestablish a connection
        ENCRYPT_CUSTOM_START(25),
        ENCRYPT_CUSTOM_ANONCE(26),
        ENCRYPT_CUSTOM_SNONCE(27),
        ENCRYPT_CUSTOM_DONE(28),
        UPDATE_TIMESTAMP(30), //Used to enable timestamp distribution over the mesh
        UPDATE_CONNECTION_INTERVAL(31), //Instructs a node to use a different connection interval
        ASSET_LEGACY(32),
        CAPABILITY(33),
        ASSET_GENERIC(34),
        SIG_MESH_SIMPLE(35), //A lightweight wrapper for SIG mesh access layer messages
        MODULE_MESSAGES_START(50),
        MODULE_CONFIG(50), //Used for many different messages that set and get the module config
        MODULE_TRIGGER_ACTION(51), //Trigger some custom module action
        MODULE_ACTION_RESPONSE(52), //Response on a triggered action
        MODULE_GENERAL(53), //A message), generated by the module not as a response to an action), e.g. an event
        MODULE_RAW_DATA(54),
        MODULE_RAW_DATA_LIGHT(55),
        COMPONENT_ACT(58), //Actuator messages
        COMPONENT_SENSE(59), //Sensor messages
        MODULE_MESSAGES_END(59),
        TIME_SYNC(60),
        DEAD_DATA(61), //Used by the MeshAccessConnection when malformed data was received.
        DATA_1(80),
        DATA_1_VITAL(81),
        CLC_DATA(83),
        RESERVED_BIT_START(128),
        RESERVED_BIT_END(255),
        ;

        private final int type;

        private MessageType(int type) {
            this.type = type;
        }

        public int getType() {
            return type;
        }
    }

    public enum FmKeyId {
        ZERO(0),
        NODE(1),
        NETWORK(2),
        BASE_USER(3),
        ORGANIZATION(4),
        RESTRAINED(5),
        USER_DERIVED_START(10),
        ;

        private int keyId;

        private FmKeyId(int keyId) {
            this.keyId = keyId;
        }

        public int getKeyId() {
            return keyId;
        }
    }

    public enum DeliveryOption {
        INVALID,
        WRITE_CMD,
        WRITE_REQ,
        NOTIFICATION
    }

}



