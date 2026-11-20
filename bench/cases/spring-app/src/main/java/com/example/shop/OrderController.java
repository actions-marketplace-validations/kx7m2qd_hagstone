package com.example.shop;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
  private static final Path INVOICES = Paths.get("/var/shop/invoices");

  private final JdbcTemplate jdbcTemplate;
  private final ProductRepository products;

  public OrderController(JdbcTemplate jdbcTemplate, ProductRepository products) {
    this.jdbcTemplate = jdbcTemplate;
    this.products = products;
  }

  @GetMapping
  public List<Map<String, Object>> byStatus(@RequestParam String status, @RequestParam(defaultValue = "created_at") String sort) {
    String sql = "SELECT id, total, status FROM orders WHERE status = '" + status + "' ORDER BY " + sort;
    // expect: java-sql-injection
    return jdbcTemplate.queryForList(sql);
  }

  @GetMapping("/mine")
  public List<Map<String, Object>> mine(@RequestParam String customer) {
    return jdbcTemplate.queryForList("SELECT id, total FROM orders WHERE customer = ?", customer);
  }

  @GetMapping("/{id}")
  public Map<String, Object> one(@PathVariable long id) {
    return jdbcTemplate.queryForMap("SELECT * FROM orders WHERE id = " + id);
  }

  @GetMapping("/products")
  public List<Map<String, Object>> products(@RequestParam String category) {
    // Cross-file: the query is built in ProductRepository.
    return products.byCategory(category);
  }

  @GetMapping("/invoice/{name}")
  public byte[] invoice(@PathVariable String name) throws IOException {
    // expect: java-path-traversal
    return Files.readAllBytes(INVOICES.resolve(name));
  }

  @GetMapping("/invoice-safe/{name}")
  public byte[] invoiceSafe(@PathVariable String name) throws IOException {
    Path file = INVOICES.resolve(Paths.get(name).getFileName().toString()).normalize();
    if (!file.startsWith(INVOICES)) throw new IllegalArgumentException("bad name");
    return Files.readAllBytes(file);
  }

  @PostMapping("/export")
  public String export(@RequestParam String format) throws IOException {
    // expect: java-command-injection
    Process p = new ProcessBuilder("sh", "-c", "/opt/shop/export.sh --format " + format).start();
    return "started " + p.pid();
  }

  @PostMapping("/export-safe")
  public String exportSafe(@RequestParam String format) throws IOException {
    if (!List.of("csv", "json").contains(format)) throw new IllegalArgumentException("format");
    Process p = new ProcessBuilder("/opt/shop/export.sh", "--format", format).start();
    return "started " + p.pid();
  }
}
