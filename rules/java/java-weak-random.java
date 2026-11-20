import java.security.SecureRandom;
import java.util.Random;
import javax.servlet.http.*;

public class Tokens {
  void rememberMe(HttpServletRequest req, HttpServletResponse resp) {
    String key = Long.toString(new Random().nextLong());
    // ruleid: java-weak-random
    resp.addCookie(new Cookie("rememberMe", key));
  }

  void session(HttpServletRequest req) {
    String token = Double.toString(Math.random()).substring(2);
    // ruleid: java-weak-random
    req.getSession().setAttribute("csrf", token);
  }

  void bytes(HttpServletResponse resp) {
    byte[] buf = new byte[16];
    new Random().nextBytes(buf);
    String t = java.util.Base64.getEncoder().encodeToString(buf);
    // ruleid: java-weak-random
    resp.setHeader("X-Reset-Token", t);
  }

  void setter(User u) {
    // ruleid: java-weak-random
    u.setResetToken(String.valueOf(new Random().nextInt()));
  }

  void secure(HttpServletResponse resp) throws Exception {
    Random rng = SecureRandom.getInstance("SHA1PRNG");
    String key = Long.toString(rng.nextLong());
    // ok: java-weak-random
    resp.addCookie(new Cookie("rememberMe", key));
  }

  void jitter() throws Exception {
    // ok: java-weak-random
    Thread.sleep(100 + new Random().nextInt(50));
  }

  interface User { void setResetToken(String t); }
}
