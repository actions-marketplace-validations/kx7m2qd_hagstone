import { describe, expect, it } from "vitest";
import { pathScope } from "../src/core/scope.js";

describe("pathScope", () => {
  it("recognises JS and Python tests", () => {
    for (const p of ["src/a.test.ts", "__tests__/x.js", "tests/test_api.py", "pkg/api_test.py", "conftest.py"]) {
      expect(pathScope(p), p).toBe("test");
    }
  });

  it("recognises Java and Kotlin tests by directory and class name", () => {
    for (const p of [
      "src/test/java/com/acme/UserServiceTest.java",
      "app/src/main/java/com/acme/OrderControllerTests.java",
      "core/OrderRepositoryIT.java",
      "core/TestFixtures.java",
      "core/PaymentTest.kt",
    ]) {
      expect(pathScope(p), p).toBe("test");
    }
  });

  it("doesn't mistake ordinary class names for tests", () => {
    for (const p of ["src/main/java/com/acme/Contest.java", "src/main/java/com/acme/Latest.java", "src/main/java/com/acme/AUDIT.java", "src/main/java/com/acme/Testimonial.java"]) {
      expect(pathScope(p), p).toBe("prod");
    }
  });

  it("puts examples apart", () => {
    expect(pathScope("examples/spring/App.java")).toBe("example");
  });
});
