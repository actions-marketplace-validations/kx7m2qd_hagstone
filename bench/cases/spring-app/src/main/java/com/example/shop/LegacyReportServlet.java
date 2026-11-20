package com.example.shop;

import java.io.IOException;
import java.io.PrintWriter;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

public class LegacyReportServlet extends HttpServlet {
  private DirContext directory;

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String title = request.getParameter("title");
    PrintWriter out = response.getWriter();
    // expect: java-xss
    out.println("<h1>" + title + "</h1>");
    out.println("<h2>" + HtmlUtils.htmlEscape(request.getParameter("subtitle")) + "</h2>");

    // expect: java-trust-boundary
    request.getSession().setAttribute("reportOwner", request.getParameter("owner"));
  }

  protected void lookupManager(HttpServletRequest request) throws Exception {
    String team = request.getParameter("team");
    SearchControls controls = new SearchControls();
    // expect: java-ldap-injection
    directory.search("ou=staff,dc=shop,dc=example", "(&(objectClass=person)(team=" + team + "))", controls);
    directory.search("ou=staff,dc=shop,dc=example", "(&(objectClass=person)(team={0}))", new Object[] {team}, controls);
  }
}
