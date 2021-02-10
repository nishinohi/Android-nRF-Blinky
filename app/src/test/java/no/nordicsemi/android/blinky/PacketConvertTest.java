package no.nordicsemi.android.blinky;

import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import no.nordicsemi.android.ble.data.Data;
import no.nordicsemi.android.blinky.profile.module.EnrollmentModule;
import no.nordicsemi.android.blinky.profile.packet.FruityDataSplitter;
import no.nordicsemi.android.blinky.profile.packet.FruityPacket;

import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.*;

public class PacketConvertTest {
    @Test
    public void packet_Create_Encrypt_Custom_Start_Test() {
        FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_START, 259, 100, 1,
                FruityPacket.FmKeyId.NODE, 1, 57);
        byte expect[] = {0x19, 0x03, 0x01, 0x64, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, (byte) 0xE5};
        assertThat("convert", FruityPacket.createEncryptCustomStartPacket(packet), is(expect));
    }

    @Test
    public void first_handshake_Test() {
        FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_START, 259, 0, 1,
                FruityPacket.FmKeyId.NODE, 0, 0);
        byte expect[] = {25, 3, 1, 0, 0, 1, 1, 0, 0, 0, 0};
        assertThat("convert", FruityPacket.createEncryptCustomStartPacket(packet), is(expect));
    }

    @Test
    public void sNonce_Convert_Test() {
        int sNonce[] = new int[]{1689834492, 434638765};
        FruityPacket.ConnPacketEncryptCustomSNonce customSNonce = new FruityPacket.ConnPacketEncryptCustomSNonce(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_SNONCE, 1, 2,
                sNonce[0], sNonce[1]);
        byte[] expect = new byte[]{0x1B, 0x01, 0x00, 0x02, 0x00, (byte) 0xFC, (byte) 0xD3, (byte) 0xB8, 0x64, (byte) 0xAD, 0x0F, (byte) 0xE8, 0x19};
        assertThat("snonce", FruityPacket.createEncryptCustomSNonce(customSNonce), is(expect));
    }

    @Test
    public void aNonce_First_Second_Test() {
        Data data = new Data(new byte[]{0x1A, 0x3, 0x1, 0x3, 0x1, 0x41, 0x32, (byte) 0xDE, (byte) 0x95, (byte) 0xE3, (byte) 0xE2, 0x7A, 0x6});
        int expext[] = new int[]{-1780600255, 108716771};
        assertThat("anonce", FruityPacket.readEncryptCustomANonce(data), is(expext));
    }

    @Test
    public void generate_SecretKye_From_ANonce_Test() throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte plainText[] = new byte[]{0x01, 0x00, 0x1D, 0x4C, (byte) 0xFA, 0x4E, 0x32, 0x19, 0x68, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0};
        byte secretKey[] = new byte[]{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte expect[] = new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9};
        assertThat("encrypt", FruityPacket.generateSecretKey(plainText, new SecretKeySpec(secretKey, "AES")), is(expect));
    }

    @Test
    public void create_ANonce_Plaint_Text_For_Secret_Key_Test() {
        int aNonce[] = new int[]{1325026333, 711465266};
        int nodeId = FruityPacket.nodeId;
        byte expect[] = new byte[]{
                0x77, 0x02, 0x1D, 0x4C, (byte) 0xFA, 0x4E, 0x32, 0x19, 0x68, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        assertThat("plainText", FruityPacket.createPlainTextForSecretKey(FruityPacket.nodeId, aNonce), is(expect));
    }

    @Test
    public void get_Sender_Id_From_Packet_Header_Test() {
        // sender, (byte)0x 259
        byte packet[] = {0x01, 0x03, 0x01, 0x64, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00};
        assertThat("senderId", FruityPacket.getSenderId(new Data(packet)), is(259));
    }

    @Test
    public void encrypt_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        byte plainText[] = new byte[]{0x1B, 0x01, 0x00, 0x02, 0x00, (byte) 0xFC, (byte) 0xD3, (byte) 0xB8, 0x64, (byte) 0xAD, 0x0F, (byte) 0xE8, 0x19, 0x00, 0x00, 0x00};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte[] expect = new byte[]{(byte) 0x79, (byte) 0x65, (byte) 0xA5, (byte) 0xB6, (byte) 0xA6, (byte) 0xA7, (byte) 0x58, (byte) 0x89, (byte) 0x0D, (byte) 0xE8, (byte) 0x77, (byte) 0xED, (byte) 0xDC, (byte) 0xCA, (byte) 0xCA, (byte) 0x47, (byte) 0x57};
        assertThat("encrypt", FruityPacket.encryptPacketWithMIC(plainText, 13, aNonce, sessionKey), is(expect));
    }

    @Test
    public void generate_MIC_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte encryptedPacket[] = new byte[]{0x79, 0x65, (byte) 0xA5, (byte) 0xB6, (byte) 0xA6, (byte) 0xA7, 0x58, (byte) 0x89, 0x0D, (byte) 0xE8, 0x77, (byte) 0xED, (byte) 0xDC, 0x26, 0x69, (byte) 0xE4};
        byte[] expect = new byte[]{(byte) 0xCA, (byte) 0xCA, (byte) 0x47, (byte) 0x57};
        byte xoredMic[];
        try {
            xoredMic = FruityPacket.generateMIC(aNonce, sessionKey, encryptedPacket, 13);
        } catch (Exception e) {
            xoredMic = null;
        }
        assertThat("encrypt", xoredMic, is(expect));
    }

    @Test
    public void decrypt_MIC_Check_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte[] encryptedPacket = new byte[]{(byte) 0x79, (byte) 0x65, (byte) 0xA5, (byte) 0xB6, (byte) 0xA6, (byte) 0xA7, (byte) 0x58, (byte) 0x89, (byte) 0x0D, (byte) 0xE8, (byte) 0x77, (byte) 0xED, (byte) 0xDC, (byte) 0xCA, (byte) 0xCA, (byte) 0x47, (byte) 0x57};
        assertThat("MIC Check", FruityPacket.checkMICValidation(encryptedPacket, aNonce, sessionKey), is(true));
    }

    @Test
    public void decrypt_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte[] encryptedPacket = new byte[]{(byte) 0x79, (byte) 0x65, (byte) 0xA5, (byte) 0xB6, (byte) 0xA6, (byte) 0xA7, (byte) 0x58, (byte) 0x89, (byte) 0x0D, (byte) 0xE8, (byte) 0x77, (byte) 0xED, (byte) 0xDC, (byte) 0xCA, (byte) 0xCA, (byte) 0x47, (byte) 0x57};
        byte[] expect = new byte[]{(byte) 0x1B, (byte) 0x01, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0xFC, (byte) 0xD3, (byte) 0xB8, (byte) 0x64, (byte) 0xAD, (byte) 0x0F, (byte) 0xE8, (byte) 0x19};
        assertThat("encrypt", FruityPacket.decryptPacket(encryptedPacket, encryptedPacket.length, aNonce, sessionKey), is(expect));
    }

    // if data lower than max length, you don't add split header
    @Test
    public void chunk_Encrypt_Non_Split_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        FruityPacket.ConnPacketEncryptCustomSNonce sNonce = new FruityPacket.ConnPacketEncryptCustomSNonce(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_SNONCE, 1, 2, 1689834492, 434638765);
        byte[] plainText = FruityPacket.createEncryptCustomSNonce(sNonce);
        FruityDataSplitter splitter = new FruityDataSplitter(aNonce, sessionKey);
        byte[] expect = new byte[]{(byte) 0x79, (byte) 0x65, (byte) 0xA5, (byte) 0xB6, (byte) 0xA6, (byte) 0xA7, (byte) 0x58, (byte) 0x89, (byte) 0x0D, (byte) 0xE8, (byte) 0x77, (byte) 0xED, (byte) 0xDC, (byte) 0xCA, (byte) 0xCA, (byte) 0x47, (byte) 0x57};
        assertThat("Non Split", splitter.chunk(plainText, 0, 23), is(expect));
    }

    @Test
    public void chunk_Encrypt_Split_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte[] plainText = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        FruityDataSplitter splitter = new FruityDataSplitter(aNonce, sessionKey);
        int index = 0;
        byte[] target = new byte[0];
        byte[] splitData = new byte[0];
        while (splitData != null) {
            splitData = splitter.chunk(plainText, index++, 23);
            if (splitData != null) {
                target = new byte[splitData.length];
                System.arraycopy(splitData, 0, target, 0, splitData.length);
            }
        }
        assertThat("split length", target.length, is(13));
    }

    @Test
    public void chunk_Encrypt_First_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte[] plainText = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        FruityDataSplitter splitter = new FruityDataSplitter(aNonce, sessionKey);
        byte[] expect = new byte[]{(byte) 0x72, (byte) 0x64, (byte) 0xA4, (byte) 0xB6, (byte) 0xA5, (byte) 0x5F, (byte) 0x8E, (byte) 0x30, (byte) 0x6B, (byte) 0x46, (byte) 0x7C, (byte) 0x00, (byte) 0xC4, (byte) 0x24, (byte) 0x6A, (byte) 0xE0, (byte) 0x8F, (byte) 0x6E, (byte) 0x5D, (byte) 0x4F};
        assertThat("Split chunk first", splitter.chunk(plainText, 0, 23), is(expect));
    }

    @Test
    public void chunk_Encrypt_Last_Test() {
        // first, (byte)0x 0x4EFA4C1D
        // second, (byte)0x 0x2A681932
        int aNonce[] = new int[]{1325026333, 711465266};
        SecretKey sessionKey = new SecretKeySpec(new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9}, "AES");
        byte[] plainText = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] expect = new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0xA0, (byte) 0xB5, (byte) 0xA4, (byte) 0x58, (byte) 0x8F, (byte) 0x34, (byte) 0x68, (byte) 0x47, (byte) 0x7B, (byte) 0x01, (byte) 0xC0, (byte) 0x1C, (byte) 0xFB, (byte) 0x4B, (byte) 0x12};
        FruityDataSplitter splitter = new FruityDataSplitter(aNonce, sessionKey);
        int index = 0;
        byte[] target = new byte[0];
        byte[] splitData = new byte[0];
        while (splitData != null) {
            splitData = splitter.chunk(plainText, index++, 23);
            if (splitData != null) {
                target = new byte[splitData.length];
                System.arraycopy(splitData, 0, target, 0, splitData.length);
            }
        }
        assertThat("Split chunk last", target, is(expect));
    }

    // if data lower than max length, you don't add split header
    @Test
    public void chunk_Non_Encrypt_Non_Split_Test() {
        FruityPacket.ConnPacketEncryptCustomSNonce sNonce = new FruityPacket.ConnPacketEncryptCustomSNonce(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_SNONCE, 1, 2, 1689834492, 434638765);
        byte[] plainText = FruityPacket.createEncryptCustomSNonce(sNonce);
        FruityDataSplitter splitter = new FruityDataSplitter(null, null);
        byte[] expect = new byte[]{(byte) 0x1B, (byte) 0x01, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0xFC, (byte) 0xD3, (byte) 0xB8, (byte) 0x64, (byte) 0xAD, (byte) 0x0F, (byte) 0xE8, (byte) 0x19};
        assertThat("Non Split", splitter.chunk(plainText, 0, 20), is(expect));
    }

    @Test
    public void chunk_Non_Encrypt_Split_Test() {
        byte[] plainText = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        FruityDataSplitter splitter = new FruityDataSplitter(null, null);
        int index = 0;
        byte[] target = new byte[0];
        byte[] splitData = new byte[0];
        while (splitData != null) {
            splitData = splitter.chunk(plainText, index++, 20);
            if (splitData != null) {
                target = new byte[splitData.length];
                System.arraycopy(splitData, 0, target, 0, splitData.length);
            }
        }
        assertThat("split length", target.length, is(14));
    }

    @Test
    public void chunk_Non_Encrypt_First_Test() {
        byte[] plainText = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        FruityDataSplitter splitter = new FruityDataSplitter(null, null);
        byte[] expect = new byte[]{0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03};
        assertThat("Split chunk first", splitter.chunk(plainText, 0, 20), is(expect));
    }

    @Test
    public void chunk_Non_Encrypt_Last_Test() {
        byte[] plainText = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] expect = new byte[]{0x11, 0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        FruityDataSplitter splitter = new FruityDataSplitter(null, null);
        int index = 0;
        byte[] target = new byte[0];
        byte[] splitData = new byte[0];
        while (splitData != null) {
            splitData = splitter.chunk(plainText, index++, 23);
            if (splitData != null) {
                target = new byte[splitData.length];
                System.arraycopy(splitData, 0, target, 0, splitData.length);
            }
        }
        assertThat("Split chunk last", target, is(expect));
    }

    @Test
    public void get_Index_For_Serial_Test() {
        String test = "FMDVR";
        assertThat("serial index convert", FruityPacket.getIndexForSerial(test), is(2675293));
    }

    @Test
    public void create_Enrollment_Module_Set_Enrollment_BySerial_Message_Packet_Test() {
        EnrollmentModule.EnrollmentModuleSetEnrollmentBySerialMessage message =
                new EnrollmentModule.EnrollmentModuleSetEnrollmentBySerialMessage(
                        FruityPacket.getIndexForSerial("FMDVR"), (short) 100, (short) 101,
                        new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4},
                        new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4},
                        (byte) 100, true);
        byte[] packet = new EnrollmentModule().createEnrollmentModuleSetEnrollmentBySerialMessagePacket(message);
        byte[] expect = {
                0x5D, (byte) 0xD2, 0x28, 0x00, 0x64, 0x00, 0x65, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                (byte) 0xE4};
        assertThat("enroll", packet, is(expect));
    }

    @Test
    public void create_Enrollment_Module_Set_Enrollment_BySerial_Message_Action_Packet_Test() {
        EnrollmentModule.EnrollmentModuleSetEnrollmentBySerialMessage message =
                new EnrollmentModule.EnrollmentModuleSetEnrollmentBySerialMessage(
                        FruityPacket.getIndexForSerial("FMDVR"), (short) 100, (short) 101,
                        new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4},
                        new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, new byte[]{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4},
                        (byte) 100, true);
        EnrollmentModule enroll = new EnrollmentModule();
        byte[] packet = enroll.createEnrollmentModuleSetEnrollmentBySerialMessagePacket(message);
        byte[] expect = {
                0x33, 0x77, 0x02, 0x64, 0x00, 0x05, 0x00, 0x00,
                0x5D, (byte) 0xD2, 0x28, 0x00, 0x64, 0x00, 0x65, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                (byte) 0xE4};
        byte[] actionPacket = enroll.createSendModuleActionMessagePacket(FruityPacket.MessageType.MODULE_TRIGGER_ACTION, (short)100, (byte)0,
                EnrollmentModule.EnrollmentModuleTriggerActionMessages.SET_ENROLLMENT_BY_SERIAL.getActionType(),
                packet, packet.length, false);
        assertThat("action", actionPacket, is(expect));
    }
}

