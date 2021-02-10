package no.nordicsemi.android.blinky.profile.module;

public class StatusReporterModule extends Module {
    public StatusReporterModule() {
        super("status", (byte) 3);
    }

    public static enum StatusModuleTriggerActionMessages {
        GET_STATUS((byte) 1),
        ;
        private byte actionType;
        StatusModuleTriggerActionMessages(byte b) {
            this.actionType = b;
        }

        public byte getActionType() {
            return actionType;
        }
    }
}
