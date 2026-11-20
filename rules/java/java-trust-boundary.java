import javax.servlet.http.*;

public class Sessions {
  void store(HttpServletRequest req) {
    HttpSession session = req.getSession();
    // ruleid: java-trust-boundary
    session.setAttribute("role", req.getParameter("role"));
  }

  void chained(HttpServletRequest req) {
    // ruleid: java-trust-boundary
    req.getSession().setAttribute(req.getHeader("X-Key"), "1");
  }

  void constant(HttpServletRequest req) {
    // ok: java-trust-boundary
    req.getSession().setAttribute("visited", Boolean.TRUE);
  }

  void numeric(HttpServletRequest req) {
    long page = Long.parseLong(req.getParameter("page"));
    // ok: java-trust-boundary
    req.getSession().setAttribute("page", page);
  }
}
