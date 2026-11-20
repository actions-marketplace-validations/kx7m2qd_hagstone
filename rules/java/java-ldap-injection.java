import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.support.LdapEncoder;

public class Ldap {
  DirContext ctx;

  void search(HttpServletRequest req) throws Exception {
    String user = req.getParameter("user");
    SearchControls sc = new SearchControls();
    // ruleid: java-ldap-injection
    ctx.search("ou=users,dc=example,dc=com", "(uid=" + user + ")", sc);
  }

  void parameterized(HttpServletRequest req) throws Exception {
    SearchControls sc = new SearchControls();
    // ok: java-ldap-injection
    ctx.search("ou=users,dc=example,dc=com", "(uid={0})", new Object[] {req.getParameter("user")}, sc);
  }

  void encoded(HttpServletRequest req) throws Exception {
    String user = LdapEncoder.filterEncode(req.getParameter("user"));
    // ok: java-ldap-injection
    ctx.search("ou=users,dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
  }
}
