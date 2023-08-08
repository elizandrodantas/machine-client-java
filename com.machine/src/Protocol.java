import java.nio.ByteBuffer;

public class Protocol {
    private byte[] input;
    private byte[] iv;
    private byte[] key;
    private byte[] message;

    public Protocol(byte[] b64) {
        this.input = b64;

        if (input.length < 32) {
            throw new IllegalArgumentException("protocol invalid length");
        }

        this.iv = this.sliceArray(input, 0, 16);
        this.key = this.sliceArray(input, input.length - 16, input.length);
        this.message = this.sliceArray(input, 16, input.length - 16);
    }

    private byte[] sliceArray(byte[] array, int start, int end) {
        byte[] result = new byte[end - start];
        System.arraycopy(array, start, result, 0, end - start);
        return result;
    }

    public byte[] getIv() {
        return this.iv;
    }

    public byte[] getKey() {
        return this.key;
    }

    public byte[] getMessage() {
        return this.message;
    }

    public byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + message.length + key.length);
        buffer.put(iv);
        buffer.put(message);
        buffer.put(key);
        return buffer.array();
    }

    public String toBase64() {
        return java.util.Base64.getEncoder().encodeToString(this.toByteArray());
    }
}
