import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

public class Hashes {
  byte[] md5(byte[] in) throws Exception {
    // ruleid: java-weak-hash
    return MessageDigest.getInstance("MD5").digest(in);
  }

  byte[] sha1(byte[] in) throws Exception {
    // ruleid: java-weak-hash
    return java.security.MessageDigest.getInstance("sha1", "SUN").digest(in);
  }

  String commons(String s) {
    // ruleid: java-weak-hash
    return DigestUtils.md5Hex(s);
  }

  byte[] sha256(byte[] in) throws Exception {
    // ok: java-weak-hash
    return MessageDigest.getInstance("SHA-256").digest(in);
  }

  String commonsStrong(String s) {
    // ok: java-weak-hash
    return DigestUtils.sha256Hex(s);
  }
}
