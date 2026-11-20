import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.*;
import org.w3c.dom.Document;

public class XPathQ {
  Document doc;

  void compile(HttpServletRequest req) throws Exception {
    XPath xp = XPathFactory.newInstance().newXPath();
    String id = req.getParameter("id");
    // ruleid: java-xpath-injection
    xp.compile("/users/user[@id='" + id + "']").evaluate(doc);
  }

  void evaluate(HttpServletRequest req) throws Exception {
    XPath xp = XPathFactory.newInstance().newXPath();
    // ruleid: java-xpath-injection
    xp.evaluate("/users/user[name='" + req.getHeader("X-Name") + "']/email", doc);
  }

  void variable(HttpServletRequest req) throws Exception {
    XPath xp = XPathFactory.newInstance().newXPath();
    String id = req.getParameter("id");
    xp.setXPathVariableResolver(q -> id);
    // ok: java-xpath-injection
    xp.evaluate("/users/user[@id=$id]", doc);
  }
}
