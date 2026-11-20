import java.io.PrintWriter;
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;

public class Pages {
  void direct(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    // ruleid: java-xss
    resp.getWriter().println("<h1>Hello " + req.getParameter("name") + "</h1>");
  }

  void viaLocal(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    PrintWriter out = resp.getWriter();
    String q = req.getQueryString();
    // ruleid: java-xss
    out.write("You searched for " + q);
  }

  void cookie(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    for (Cookie c : req.getCookies()) {
      // ruleid: java-xss
      resp.getWriter().format("<p>%s</p>", c.getValue());
    }
  }

  void escaped(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String name = HtmlUtils.htmlEscape(req.getParameter("name"));
    // ok: java-xss
    resp.getWriter().println("<h1>Hello " + name + "</h1>");
  }

  void fileWriter(HttpServletRequest req) throws Exception {
    PrintWriter log = new PrintWriter("audit.log");
    // ok: java-xss
    log.println("search: " + req.getParameter("q"));
  }
}
