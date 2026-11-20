import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

public class Commands {
  void exec(HttpServletRequest req) throws Exception {
    Runtime r = Runtime.getRuntime();
    // ruleid: java-command-injection
    r.exec("ping -c 1 " + req.getParameter("host"));
  }

  void envInjection(HttpServletRequest req) throws Exception {
    String[] env = {"FOO=" + req.getHeader("X-Foo")};
    // ruleid: java-command-injection
    Runtime.getRuntime().exec(new String[] {"sh", "-c", "echo $FOO"}, env);
  }

  void builderList(HttpServletRequest req) throws Exception {
    List<String> args = new ArrayList<>();
    args.add("sh");
    args.add("-c");
    args.add("echo " + req.getParameter("msg"));
    ProcessBuilder pb = new ProcessBuilder();
    // ruleid: java-command-injection
    pb.command(args);
    pb.start();
  }

  @PostMapping("/convert")
  public void spring(@RequestParam String file) throws Exception {
    // ruleid: java-command-injection
    new ProcessBuilder("convert", file, "out.png").start();
  }

  @PostMapping("/export")
  public void allowlisted(@RequestParam String format) throws Exception {
    if (!java.util.List.of("csv", "json").contains(format)) throw new IllegalArgumentException(format);
    // ok: java-command-injection
    new ProcessBuilder("/opt/export.sh", "--format", format).start();
  }

  void validated(HttpServletRequest req) throws Exception {
    String host = req.getParameter("host");
    if (!host.matches("[a-z0-9.-]+")) return;
    // ok: java-command-injection
    new ProcessBuilder("ping", "-c", "1", host).start();
  }

  void constant() throws Exception {
    // ok: java-command-injection
    Runtime.getRuntime().exec(new String[] {"ls", "-l", "/tmp"});
  }

  void numeric(HttpServletRequest req) throws Exception {
    int n = Integer.parseInt(req.getParameter("n"));
    // ok: java-command-injection
    new ProcessBuilder("head", "-n", String.valueOf(n), "/var/log/app.log").start();
  }
}
