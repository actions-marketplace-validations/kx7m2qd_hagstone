package com.example.shop;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class AccountService {
  private final Random random = new Random();
  private final SecureRandom secureRandom = new SecureRandom();

  public String legacyPasswordHash(String password) throws Exception {
    // expect: java-weak-hash
    MessageDigest md = MessageDigest.getInstance("MD5");
    return Base64.getEncoder().encodeToString(md.digest(password.getBytes(StandardCharsets.UTF_8)));
  }

  public byte[] checksum(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  public byte[] encryptCard(SecretKey key, byte[] pan) throws Exception {
    // expect: java-weak-cipher
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(pan);
  }

  public void issueResetCookie(HttpServletResponse response) {
    String token = Long.toHexString(random.nextLong());
    // expect: java-weak-random
    Cookie reset = new Cookie("reset", token);
    reset.setSecure(true);
    reset.setHttpOnly(true);
    response.addCookie(reset);
  }

  public void issueSessionCookie(HttpServletResponse response) {
    byte[] buf = new byte[32];
    secureRandom.nextBytes(buf);
    Cookie session = new Cookie("sid", Base64.getUrlEncoder().encodeToString(buf));
    session.setHttpOnly(true);
    // expect: java-insecure-cookie
    response.addCookie(session);
  }

  public long backoffMillis(int attempt) {
    return (1L << attempt) * 100 + random.nextInt(100);
  }
}
