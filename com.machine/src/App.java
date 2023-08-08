import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

public class App {
    byte[] key = new byte[16];
    byte[] iv = new byte[16];

    String json = "{\"machine_id\": \"e1b78f6d-0b3e-4606-b708-1f1fbbd9c020\", \"machine_name\": \"test\", \"machine_plataform\": \"java\", \"expire\": 1696951958 }";

    String protocolResultTest = "AAAAAAAAAAAAAAAAAAAAAB3LJrWM4kVV7ROTPegOCww90575whgGBRtPf2TBynFsM773rFeGm7/CTvPfE9CaQZSlmJtrZ3kBmpzql/3lpL9OY3xEbEm0+FTsxdjyv4vCpCzBcXjgTCILEt3IqKXngOf8R6WKhFQXDlMIifdCeuH8yig5rOahyRYb2j7D1bzYIi4AAAAAAAAAAAAAAAAAAAAA";

    public static void main(String[] args) throws Exception {
        System.out.println("-> starting tests");

        App app = new App();

        app.testEncryptAesCrt();
        app.testDecryptAesCrt();
        app.testEncryptWithProtocol();
        app.testDecryptToProtocol();

        System.out.println("-> successful tests");
    }

    public void testEncryptAesCrt() throws Exception {
        byte[] enc = CipherMachine.encrypt("test", key, iv);
        String encB64 = Base64.getEncoder().encodeToString(enc);

        if (!encB64.equals("Eow4oA==")) {
            throw new Exception("[testEncryptAesCrt] expected 'Eow4oA==' and received '" + encB64 + "'");
        }
    }

    public void testDecryptAesCrt() throws Exception {
        byte[] decodeEncodedB64 = Base64.getDecoder().decode("Eow4oA==");
        String dec = CipherMachine.decrypt(decodeEncodedB64, key, iv);

        if (!dec.equals("test")) {
            throw new Exception("[testDecryptAesCrt] expected 'test' and received '" + dec + "'");
        }
    }

    public void testEncryptWithProtocol() throws Exception {
        byte[] encrypt = CipherMachine.encrypt(json, key, iv);
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypt.length + key.length);
        buffer.put(iv);
        buffer.put(encrypt);
        buffer.put(key);

        Protocol protocol = new Protocol(buffer.array());

        if (!Arrays.equals(protocol.getKey(), key)) {
            throw new Exception("[testEncryptWithProtocol] protocol broke -> invalid key");
        }

        if (!Arrays.equals(protocol.getIv(), iv)) {
            throw new Exception("[testEncryptWithProtocol] protocol broke -> invalid iv");
        }

        if (!Arrays.equals(protocol.getMessage(), encrypt)) {
            throw new Exception("[testEncryptWithProtocol] protocol broke -> invalid message");
        }

        if (!protocol.toBase64().equals(protocolResultTest)) {
            throw new Exception("[testEncryptWithProtocol] the protocol did not correctly concatenate the bytes");
        }
    }

    public void testDecryptToProtocol() throws Exception {
        byte[] byteDecode64 = Base64.getDecoder().decode(protocolResultTest);

        Protocol protocol = new Protocol(byteDecode64);

        String dec = CipherMachine.decrypt(protocol.getMessage(), protocol.getKey(), protocol.getIv());

        if (!dec.equals(json)) {
            throw new Exception("[testDecryptToProtocol] message was not decoded correctly");
        }

        if (!Arrays.equals(protocol.getKey(), key)) {
            throw new Exception("[testDecryptToProtocol] protocol broke -> invalid key");
        }

        if (!Arrays.equals(protocol.getIv(), iv)) {
            throw new Exception("[testDecryptToProtocol] protocol broke -> invalid iv");
        }
    }

}
