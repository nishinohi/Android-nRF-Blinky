package no.nordicsemi.android.blinky.profile.packet;


import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import no.nordicsemi.android.ble.data.Data;

public class FruityPacket {
    public static final int nodeId = 631;
    public static final int NODE_ID_VIRTUAL_BASE = 2000;
    public static final int MESH_ACCESS_MIC_LENGTH = 4;
    public static final int FRUITY_MTU = 20;
    public static final SecretKey secretKey = new SecretKeySpec(
//            new byte[]{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
            new byte[]{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
            "AES"
    );
    public static int INVALID_SERIAL_NUMBER_INDEX = 0xFFFFFFFF;

    public static final String CMD_KEY = "CMD";
    public static final String SERIAL_INDEX_KEY = "SERIAL_INDEX";
    public static final String NEW_NODE_ID_KEY = "NEW_NODE_ID";

    private static byte[] createConnHeaderBytes(ConnPacketHeader header) {
        byte[] headerBytes = new byte[ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER];
        int offset = 0;
        headerBytes[offset++] = header.messageType.getTypeValue();
        byte[] temp = convertIntToBytes(header.sender, ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(temp, 0, headerBytes, offset, 2);
        offset += 2;
        temp = convertIntToBytes(header.receiver, ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(temp, 0, headerBytes, offset, 2);
        return headerBytes;
    }

    public static byte[] encryptPacketWithMIC(byte[] plainPacket, int packetLen, int[] encryptionNonce, SecretKey sessionEncryptionKey) {
        if (encryptionNonce.length != 2) return null;

        Log.d("FM", "Encrypting: " + Arrays.toString(plainPacket) + "(" + packetLen + ")" + " with nonce: " + encryptionNonce[1]);
        byte[] packetZeroPadding = new byte[16];
        System.arraycopy(plainPacket, 0, packetZeroPadding, 0, plainPacket.length);
        byte[] mic;
        byte[] encryptPacket;
        try {
            byte[] encryptNonceClearTextForKeyStream = new byte[16];
            System.arraycopy(convertIntToBytes(encryptionNonce[0], ByteOrder.LITTLE_ENDIAN), 0, encryptNonceClearTextForKeyStream, 0, 4);
            System.arraycopy(convertIntToBytes(encryptionNonce[1], ByteOrder.LITTLE_ENDIAN), 0, encryptNonceClearTextForKeyStream, 4, 4);
            // generate key stream
            Cipher cipher = Cipher.getInstance("AES_128/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionEncryptionKey);
            byte[] encryptKeyStream = cipher.doFinal(encryptNonceClearTextForKeyStream);
            encryptPacket = xorBytes(packetZeroPadding, 0, encryptKeyStream, 0, packetZeroPadding.length);
            mic = generateMIC(encryptionNonce, sessionEncryptionKey, encryptPacket, packetLen);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        byte[] encryptPacketWithMic = new byte[packetLen + FruityPacket.MESH_ACCESS_MIC_LENGTH];
        System.arraycopy(encryptPacket, 0, encryptPacketWithMic, 0, packetLen);
        System.arraycopy(mic, 0, encryptPacketWithMic, packetLen, mic.length);
        Log.d("FM", "Encrypted with MIC: " + Arrays.toString(encryptPacketWithMic) + "(" + encryptPacketWithMic.length + ")" + " with nonce: " + encryptionNonce[1]);
        return encryptPacketWithMic;
    }

    public static byte[] decryptPacket(byte[] encryptPacket, int packetLen, int[] decryptionNonce, SecretKey sessionDecryptionKey) {
        if (decryptionNonce.length != 2) return null;

        int packetRawLen = packetLen - FruityPacket.MESH_ACCESS_MIC_LENGTH;
        // check MIC
        if (!checkMICValidation(encryptPacket, decryptionNonce, sessionDecryptionKey)) {
            Log.d("FM", "MIC is invalid");
            return null;
        }
        Log.d("FM", "Decrypting: " + encryptPacket + "(" + packetLen + ")" + " with nonce: " + decryptionNonce[1]);
        byte[] decryptNonceClearTextForKeyStream = new byte[16];
        System.arraycopy(convertIntToBytes(decryptionNonce[0], ByteOrder.LITTLE_ENDIAN), 0, decryptNonceClearTextForKeyStream, 0, 4);
        System.arraycopy(convertIntToBytes(decryptionNonce[1], ByteOrder.LITTLE_ENDIAN), 0, decryptNonceClearTextForKeyStream, 4, 4);
        byte[] decryptKeyStream;
        try {
            Cipher cipher = Cipher.getInstance("AES_128/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionDecryptionKey);
            decryptKeyStream = cipher.doFinal(decryptNonceClearTextForKeyStream);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        byte[] decryptPacket = xorBytes(encryptPacket, 0, decryptKeyStream, 0, packetRawLen);
        Log.d("FM", "Decrypted: " + decryptPacket + "(" + packetLen + ")" + " with nonce: " + decryptionNonce[1]);
        return decryptPacket;
    }

    public static byte[] generateMIC(int[] encryptionNonceOrigin, SecretKey secretKey, byte[] encryptedPacket, int packetLen) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (encryptionNonceOrigin.length != 2 && encryptedPacket.length != 16) return null;

        // create aNonce plain text to generate key stream for mic
        int[] encryptionNonce = new int[2];
        System.arraycopy(encryptionNonceOrigin, 0, encryptionNonce, 0, encryptionNonceOrigin.length);
        encryptionNonce[1]++;
        byte[] plainTextForMicKeyStream = new byte[16];
        System.arraycopy(convertIntToBytes(encryptionNonce[0], ByteOrder.LITTLE_ENDIAN), 0, plainTextForMicKeyStream, 0, 4);
        System.arraycopy(convertIntToBytes(encryptionNonce[1], ByteOrder.LITTLE_ENDIAN), 0, plainTextForMicKeyStream, 4, 4);
        Cipher cipher = Cipher.getInstance("AES_128/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] micKeyStream = cipher.doFinal(plainTextForMicKeyStream);
        byte[] zeroPaddingEncryptPacket = new byte[16];
        System.arraycopy(encryptedPacket, 0, zeroPaddingEncryptPacket, 0, packetLen);
        byte[] xoredMic = xorBytes(micKeyStream, 0, zeroPaddingEncryptPacket, 0, micKeyStream.length);
        byte[] mic = new byte[MESH_ACCESS_MIC_LENGTH];
        System.arraycopy(cipher.doFinal(xoredMic), 0, mic, 0, MESH_ACCESS_MIC_LENGTH);
        return mic;
    }

    public static boolean checkMICValidation(byte[] encryptedPacket, int[] _decryptionNonce, SecretKey secretKey) {
        if (_decryptionNonce.length != 2) return false;

        // check MIC
        int decryptionNonce[] = new int[2];
        System.arraycopy(_decryptionNonce, 0, decryptionNonce, 0, _decryptionNonce.length);
        ++decryptionNonce[1];
        byte[] mic;
        try {
            byte[] decryptNonceClearTextForKeyStream = new byte[16];
            System.arraycopy(convertIntToBytes(decryptionNonce[0], ByteOrder.LITTLE_ENDIAN), 0, decryptNonceClearTextForKeyStream, 0, 4);
            System.arraycopy(convertIntToBytes(decryptionNonce[1], ByteOrder.LITTLE_ENDIAN), 0, decryptNonceClearTextForKeyStream, 4, 4);
            Cipher cipher = Cipher.getInstance("AES_128/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] micKeyStream = cipher.doFinal(decryptNonceClearTextForKeyStream);
            byte encryptedPacketWithoutMic[] = new byte[16];
            System.arraycopy(encryptedPacket, 0, encryptedPacketWithoutMic, 0, encryptedPacket.length - MESH_ACCESS_MIC_LENGTH);
            byte[] micTemp = xorBytes(encryptedPacketWithoutMic, 0, micKeyStream, 0, encryptedPacketWithoutMic.length);
            mic = cipher.doFinal(micTemp);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        for (int ii = 0; ii < FruityPacket.MESH_ACCESS_MIC_LENGTH; ++ii) {
            int encryptedMicIndex = encryptedPacket.length - FruityPacket.MESH_ACCESS_MIC_LENGTH + ii;
            if (mic[ii] != encryptedPacket[encryptedMicIndex]) {
                return false;
            }
        }
        return true;
    }

    public static byte[] xorBytes(byte[] src, int offsetSrc, byte[] xor, int offsetXor, int length) {
        byte[] dist = new byte[length];
        for (int ii = 0; ii < length; ++ii) {
            dist[ii] = (byte) (src[ii + offsetSrc] ^ xor[ii + offsetXor]);
        }
        return dist;
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
        byte temp[] = convertIntToBytes(packet.fmKeyId.getKeyId(), ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(temp, 0, convertPacket, offset, 4);
        offset += 4;
        temp = convertIntToBytes(packet.reserved, ByteOrder.LITTLE_ENDIAN);
        convertPacket[offset] = temp[0];
        convertPacket[offset] = (byte) (convertPacket[offset] << 2);
        temp = convertIntToBytes(packet.tunnelType, ByteOrder.LITTLE_ENDIAN);
        convertPacket[offset] = (byte) (convertPacket[offset] | temp[0]);
        return convertPacket;
    }

    public static byte[] createEncryptCustomSNonce(ConnPacketEncryptCustomSNonce packet) {
        byte convertPacket[] = new byte[ConnPacketEncryptCustomSNonce.SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_SNONCE];
        System.arraycopy(createConnHeaderBytes(packet.header), 0, convertPacket, 0, 5);
        int offset = ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER;
        System.arraycopy(convertIntToBytes(packet.sNonce[0], ByteOrder.LITTLE_ENDIAN),
                0, convertPacket, offset, 4);
        offset += 4;
        System.arraycopy(convertIntToBytes(packet.sNonce[1], ByteOrder.LITTLE_ENDIAN),
                0, convertPacket, offset, 4);
        return convertPacket;
    }

    public static int[] readEncryptCustomANonce(Data aNonce) {
        byte customANoncePacket[] = aNonce.getValue();
        int aNonceFirst = ByteBuffer.wrap(customANoncePacket, 5, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int aNonceSecond = ByteBuffer.wrap(customANoncePacket, 9, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return new int[]{aNonceFirst, aNonceSecond};
    }

    public static byte[] convertIntToBytes(int src, ByteOrder order) {
        return ByteBuffer.allocate(4).order(order).putInt(src).array();
    }

    public static byte[] convertShortToBytes(short src, ByteOrder order) {
        return ByteBuffer.allocate(2).order(order).putShort(src).array();
    }

    /**
     * Little Endian
     * centralNodeId[2byte] + First Nonce[4byte] + Second Nonce[4byte] + 0 Padding[6byte]
     *
     * @param nonce
     * @return
     */
    public static byte[] createPlainTextForSecretKey(int nodeId, int nonce[]) {
        byte plainText[] = new byte[16];
        byte[] temp = convertIntToBytes(nodeId, ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(temp, 0, plainText, 0, 2);
        temp = convertIntToBytes(nonce[0], ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(temp, 0, plainText, 2, 4);
        temp = convertIntToBytes(nonce[1], ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(temp, 0, plainText, 6, 4);
        return plainText;
    }

    public static byte[] generateSecretKey(byte[] plainText, SecretKey secretKey) {
        try {
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

    public static int getIndexForSerial(String serialNumber) {
        String serialAlphabet = "BCDFGHJKLMNPQRSTVWXYZ123456789";
        int index = 0;
        int serialLength = serialNumber.length();
        int charCounter = 0;
        for (int i = 0; i < serialLength; i++) {
            if (i == serialLength - 1 && serialNumber.charAt(0) == 'A') continue;
            char currentChar = serialNumber.charAt(serialLength - i - 1);
            int charPos = serialAlphabet.indexOf(currentChar);
            if (charPos == -1) {
                return INVALID_SERIAL_NUMBER_INDEX;
            }
            index += Math.pow(serialAlphabet.length(), charCounter) * charPos;
            charCounter++;
        }
        return index;
    }

    public static final class ConnPacketHeader {
        public MessageType messageType;
        public int sender;
        public int receiver;

        public static final int SIZEOF_CONN_PACKET_HEADER = 5;
    }

    public static final class ConnPacketModule {
        public ConnPacketModule(ConnPacketHeader header, byte moduleId, byte requestHandle, byte actionType) {
            this.header = header;
            this.moduleId = moduleId;
            this.requestHandle = requestHandle;
            this.actionType = actionType;
        }

        public static int SIZEOF_CONN_PACKET_MODULE = ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER + 3;

        private ConnPacketHeader header;
        private byte moduleId;
        private byte requestHandle;
        private byte actionType;
    }

    public static class PacketSplitHeader {
        public MessageType splitMessageType;
        public int splitCounter;

        public static int SIZEOF_CONN_PACKET_SPLIT_HEADER = 2;
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

        public final static int SIZEOF_CONN_PACKET_ENCRYPT_CUSTOM_SNONCE =
                ConnPacketHeader.SIZEOF_CONN_PACKET_HEADER + 8;
    }

    public enum MessageType {
        INVALID((byte) 0),
        SPLIT_WRITE_CMD((byte) 16), //Used if a WRITE_CMD message is split
        SPLIT_WRITE_CMD_END((byte) 17), //Used if a WRITE_CMD message is split
        CLUSTER_WELCOME((byte) 20), //The initial message after a connection setup ((byte)Sent between two nodes)
        CLUSTER_ACK_1((byte) 21), //Both sides must acknowledge the handshake ((byte)Sent between two nodes)
        CLUSTER_ACK_2((byte) 22), //Second ack ((byte)Sent between two nodes)
        CLUSTER_INFO_UPDATE((byte) 23), //When the cluster size changes), this message is used ((byte)Sent to all nodes)
        RECONNECT((byte) 24), //Sent while trying to reestablish a connection
        ENCRYPT_CUSTOM_START((byte) 25),
        ENCRYPT_CUSTOM_ANONCE((byte) 26),
        ENCRYPT_CUSTOM_SNONCE((byte) 27),
        ENCRYPT_CUSTOM_DONE((byte) 28),
        UPDATE_TIMESTAMP((byte) 30), //Used to enable timestamp distribution over the mesh
        UPDATE_CONNECTION_INTERVAL((byte) 31), //Instructs a node to use a different connection interval
        ASSET_LEGACY((byte) 32),
        CAPABILITY((byte) 33),
        ASSET_GENERIC((byte) 34),
        SIG_MESH_SIMPLE((byte) 35), //A lightweight wrapper for SIG mesh access layer messages
        MODULE_MESSAGES_START((byte) 50),
        MODULE_CONFIG((byte) 50), //Used for many different messages that set and get the module config
        MODULE_TRIGGER_ACTION((byte) 51), //Trigger some custom module action
        MODULE_ACTION_RESPONSE((byte) 52), //Response on a triggered action
        MODULE_GENERAL((byte) 53), //A message), generated by the module not as a response to an action), e.g. an event
        MODULE_RAW_DATA((byte) 54),
        MODULE_RAW_DATA_LIGHT((byte) 55),
        COMPONENT_ACT((byte) 58), //Actuator messages
        COMPONENT_SENSE((byte) 59), //Sensor messages
        MODULE_MESSAGES_END((byte) 59),
        TIME_SYNC((byte) 60),
        DEAD_DATA((byte) 61), //Used by the MeshAccessConnection when malformed data was received.
        DATA_1((byte) 80),
        DATA_1_VITAL((byte) 81),
        CLC_DATA((byte) 83),
        RESERVED_BIT_START((byte) 128),
        RESERVED_BIT_END((byte) 255),
        ;

        private final byte type;

        private MessageType(byte type) {
            this.type = type;
        }

        public byte getTypeValue() {
            return type;
        }

        public static MessageType getTypeEnum(byte typeValue) {
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

    public enum EncryptionState {
        NOT_ENCRYPTED(0),
        ENCRYPTING(1),
        ENCRYPTED(2),
        ;

        private int state;

        private EncryptionState(int state) {
            this.state = state;
        }
    }


}



