import javax.servlet.http.*;
import org.springframework.http.ResponseCookie;

public class Cookies {
  void explicitFalse(HttpServletResponse resp) {
    Cookie c = new Cookie("session", "abc");
    // ruleid: java-insecure-cookie
    c.setSecure(false);
    resp.addCookie(c);
  }

  void missing(HttpServletResponse resp) {
    Cookie c = new Cookie("session", "abc");
    c.setHttpOnly(true);
    // ruleid: java-insecure-cookie
    resp.addCookie(c);
  }

  void spring() {
    // ruleid: java-insecure-cookie
    ResponseCookie c = ResponseCookie.from("session", "abc").secure(false).build();
  }

  void secure(HttpServletResponse resp) {
    Cookie c = new Cookie("session", "abc");
    c.setSecure(true);
    c.setHttpOnly(true);
    // ok: java-insecure-cookie
    resp.addCookie(c);
  }
}
