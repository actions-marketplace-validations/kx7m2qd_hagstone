package com.example.shop;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ProductRepository {
  private final JdbcTemplate jdbc;

  public ProductRepository(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  public List<Map<String, Object>> byCategory(String category) {
    // Reached from OrderController.products with request data (cross-file).
    // expect: java-sql-injection
    return jdbc.queryForList("SELECT * FROM products WHERE category = '" + category + "'");
  }

  public List<Map<String, Object>> byCategorySafe(String category) {
    return jdbc.queryForList("SELECT * FROM products WHERE category = ?", category);
  }
}
