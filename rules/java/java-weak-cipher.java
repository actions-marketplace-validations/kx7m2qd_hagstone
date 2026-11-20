import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Ciphers {
  void des() throws Exception {
    // ruleid: java-weak-cipher
    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
  }

  void ecb() throws Exception {
    // ruleid: java-weak-cipher
    Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
  }

  void bareAes() throws Exception {
    // ruleid: java-weak-cipher
    Cipher c = Cipher.getInstance("AES");
  }

  void rc4Key(byte[] k) {
    // ruleid: java-weak-cipher
    SecretKeySpec key = new SecretKeySpec(k, "RC4");
  }

  void gcm() throws Exception {
    // ok: java-weak-cipher
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
  }

  void rsa() throws Exception {
    // ok: java-weak-cipher
    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
  }
}
