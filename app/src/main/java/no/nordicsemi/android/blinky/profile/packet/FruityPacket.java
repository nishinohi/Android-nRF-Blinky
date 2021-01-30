package no.nordicsemi.android.blinky.profile.packet;


import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import no.nordicsemi.android.ble.data.Data;

public class FruityPacket {
    public static final int nodeId = 631;
    public static final int NODE_ID_VIRTUAL_BASE = 2000;
    public static final SecretKey secretKey = new SecretKeySpec(
            new byte[]{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
            "AES"
    );

    private static byte[] createConnHeaderBytes(ConnPacketHeader header) {
        byte headerBytes[] = new byte[ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER];
        int offset = 0;
        headerBytes[offset++] = (byte) header.messageType.getTypeValue();
        byte[] temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(header.sender).array();
        System.arraycopy(temp, 0, headerBytes, offset, 2);
        offset += 2;
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(header.receiver).array();
        System.arraycopy(temp, 0, headerBytes, offset, 2);
        return headerBytes;
    }

    /**
     * reserved and tunnelType are used for 1 byte in total.
     * reserved: 6bit, tunnelType: 2bit
     *
     * @param packet
     * @return
     */
    public static byte[] createEncryptCustomStartPacket(ConnPacketEncryptCustomStart packet) {
        byte convertPacket[] = new byte[ConnPacketEncryptCustomStart.SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_START];
        System.arraycopy(createConnHeaderBytes(packet.header), 0, convertPacket, 0, 5);
        int offset = ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER;
        convertPacket[offset++] = (byte) packet.version;
        byte temp[] = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.fmKeyId.getKeyId()).array();
        System.arraycopy(temp, 0, convertPacket, offset, 4);
        offset += 4;
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.reserved).array();
        convertPacket[offset] = temp[0];
        convertPacket[offset] = (byte) (convertPacket[offset] << 2);
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.tunnelType).array();
        convertPacket[offset] = (byte) (convertPacket[offset] | temp[0]);
        return convertPacket;
    }

    public static byte[] createEncryptCustomSNonce(ConnPacketEncryptCustomSNonce packet) {
        byte convertPacket[] = new byte[ConnPacketEncryptCustomSNonce.SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_SNONCE];
        System.arraycopy(createConnHeaderBytes(packet.header), 0, convertPacket, 0, 5);
        int offset = ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER;
        System.arraycopy(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.sNonce[0]).array(),
                0, convertPacket, offset, 4);
        offset += 4;
        System.arraycopy(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packet.sNonce[1]).array(),
                0, convertPacket, offset, 4);
        return convertPacket;
    }

    public static int[] readEncryptCustomANonce(Data aNonoce) {
        byte customANoncePacket[] = aNonoce.getValue();
        int aNonceFirst = ByteBuffer.wrap(customANoncePacket, 5, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int aNonceSecond = ByteBuffer.wrap(customANoncePacket, 9, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return new int[]{aNonceFirst, aNonceSecond};
    }

    /**
     * Little Endian
     * centralNodeId[2byte] + First ANonce[4byte] + Second ANonce[4byte] + 0 Padding[6byte]
     *
     * @param aNonce
     * @return
     */
    public static byte[] createPlainTextForSecretKey(int nodeId, int aNonce[]) {
        byte plainText[] = new byte[16];
        byte[] temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(nodeId).array();
        System.arraycopy(temp, 0, plainText, 0, 2);
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(aNonce[0]).array();
        System.arraycopy(temp, 0, plainText, 2, 4);
        temp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(aNonce[1]).array();
        System.arraycopy(temp, 0, plainText, 6, 4);
        return plainText;
    }

    public static byte[] generateSecretKey(byte[] plainText, SecretKey secretKey) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            Cipher cipher = Cipher.getInstance("AES_128/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipNoPadText = cipher.doFinal(plainText);
            return cipNoPadText;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static int getSenderId(Data packet) {
        byte connectionPacketHeader[] = packet.getValue();
        return ByteBuffer.wrap(connectionPacketHeader, 1, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
    }

    public static int getReceiverId(Data packet) {
        byte connectionPacketHeader[] = packet.getValue();
        return ByteBuffer.wrap(connectionPacketHeader, 5, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
    }

    public static final class ConnPacketHeader {
        public MessageType messageType;
        public int sender;
        public int receiver;

        public static final int SIZEOF_CONN_PACKET_HEADER = 5;
    }

    public static final class ConnPacketEncryptCustomStart {
        public ConnPacketEncryptCustomStart(MessageType messageType, int sender, int receiver, int version, FmKeyId fmKeyId, int tunnelType, int reserved) {
            this.header.messageType = messageType;
            this.header.sender = sender;
            this.header.receiver = receiver;
            this.version = version;
            this.fmKeyId = fmKeyId;
            this.tunnelType = tunnelType;
            this.reserved = reserved;
        }

        public ConnPacketHeader header = new ConnPacketHeader();
        public int version;
        public FmKeyId fmKeyId;
        public int tunnelType;
        public int reserved;

        final static int SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_START =
                ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER + 6;
    }

    public static final class ConnPacketEncryptCustomSNonce {
        public ConnPacketEncryptCustomSNonce(MessageType messageType, int sender, int receiver,
                                             int sNonceFirst, int sNonceSecond) {
            header.messageType = messageType;
            header.sender = sender;
            header.receiver = receiver;
            sNonce[0] = sNonceFirst;
            sNonce[1] = sNonceSecond;
        }

        public ConnPacketHeader header = new ConnPacketHeader();
        public int sNonce[] = new int[2];

        final static int SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_SNONCE =
                ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER + 8;
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

        public int getTypeValue() {
            return type;
        }

        public static MessageType getTypeEnum(int typeValue) {
            MessageType types[] = MessageType.values();
            for (MessageType type : types) {
                if (type.getTypeValue() == typeValue) {
                    return type;
                }
            }
            return null;
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


