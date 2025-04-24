package io.springsecurity.springsecurity6x.security.tokenstore;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JTI 기반 + SHA-256 해시 + 만료 관리가 적용된 In-Memory RefreshTokenStore
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final RefreshTokenParser parser;

    public InMemoryRefreshTokenStore(RefreshTokenParser parser) {
        this.parser = parser;
    }

    @Override
    public void store(String refreshToken, String username) {
        ParsedToken pt = parser.parse(refreshToken);
        String jti = pt.getId();

        String salt = generateSalt();
        String hash = hashToken(refreshToken, salt);

        Instant expiry = Instant.now()
                .plusMillis(JwtStateStrategy.REFRESH_TOKEN_VALIDITY);
        store.put(jti, new TokenInfo(username, salt, hash, expiry));
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            ParsedToken pt = parser.parse(refreshToken);
            String jti = pt.getId();

            TokenInfo info = store.get(jti);
            if (info == null) return null;

            if (Instant.now().isAfter(info.getExpiry())) {
                store.remove(jti);
                return null;
            }
            String candidateHash = hashToken(refreshToken, info.getSalt());
            if (!candidateHash.equals(info.getTokenHash())) {
                return null;
            }
            return info.getUsername();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void remove(String refreshToken) {
        try {
            ParsedToken pt = parser.parse(refreshToken);
            store.remove(pt.getId());
        } catch (Exception ignored) {}
    }

    private String generateSalt() {
        byte[] saltBytes = new byte[16];
        secureRandom.nextBytes(saltBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);
    }

    private String hashToken(String token, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Hash 생성 실패", e);
        }
    }
}
