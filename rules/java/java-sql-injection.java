import java.sql.*;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

public class Users {
  Connection conn;
  Statement st;
  JdbcTemplate jdbc;
  EntityManager em;

  void concat(HttpServletRequest req) throws SQLException {
    String name = req.getParameter("name");
    // ruleid: java-sql-injection
    st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }

  void builder(HttpServletRequest req) throws SQLException {
    StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE name = '");
    sql.append(req.getHeader("X-User")).append("'");
    // ruleid: java-sql-injection
    st.execute(sql.toString());
  }

  void chained(HttpServletRequest req) throws SQLException {
    // ruleid: java-sql-injection
    conn.createStatement().executeQuery("SELECT * FROM t WHERE c = " + req.getParameter("c"));
  }

  void prepareConcat(HttpServletRequest req) throws SQLException {
    // ruleid: java-sql-injection
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM t ORDER BY " + req.getParameter("sort"));
    ps.executeQuery();
  }

  // Taint through a helper in the same file (intrafile analysis).
  private String where(String v) { return " WHERE name = '" + v + "'"; }
  void helper(HttpServletRequest req) throws SQLException {
    // ruleid: java-sql-injection
    st.executeQuery("SELECT * FROM users" + where(req.getParameter("n")));
  }

  @GetMapping("/users")
  public Object spring(@RequestParam("name") String name) {
    // ruleid: java-sql-injection
    return jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
  }

  @GetMapping("/search/{term}")
  public Object jpa(@PathVariable String term) {
    // ruleid: java-sql-injection
    return em.createQuery("SELECT u FROM User u WHERE u.name = '" + term + "'").getResultList();
  }

  static class Holder { static JdbcTemplate JDBCtemplate; }
  void staticField(HttpServletRequest req) {
    // ruleid: java-sql-injection
    Holder.JDBCtemplate.execute("DELETE FROM t WHERE id = '" + req.getParameter("id") + "'");
  }

  void prepared(HttpServletRequest req) throws SQLException {
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, req.getParameter("name"));
    // ok: java-sql-injection
    ps.executeQuery();
  }

  void numeric(HttpServletRequest req) throws SQLException {
    int id = Integer.parseInt(req.getParameter("id"));
    // ok: java-sql-injection
    st.executeQuery("SELECT * FROM users WHERE id = " + id);
  }

  @GetMapping("/user/{id}")
  public Object byId(@PathVariable Long id) {
    // ok: java-sql-injection
    return jdbc.queryForList("SELECT * FROM users WHERE id = " + id);
  }

  @GetMapping("/safe")
  public Object bound(@RequestParam String name) {
    // ok: java-sql-injection
    return jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
  }
}
