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

    private final SecretKey signingKey;
    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    public InMemoryRefreshTokenStore(SecretKey signingKey) {
        this.signingKey     = signingKey;
    }

    @Override
    public void store(String refreshToken, String username) {
        // 1) JWT 파싱 → JTI(claim jti) 추출
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();
        String jti = claims.getId();

        // 2) 랜덤 솔트 + 해시 생성
        String salt = generateSalt();
        String hash = hashToken(refreshToken, salt);

        // 3) 서버 측 만료 시각 계산
        Instant expiry = Instant.now().plusMillis(JwtStateStrategy.refreshTokenValidity);

        // 4) 저장
        store.put(jti, new TokenInfo(username, salt, hash, expiry));
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody();
            String jti = claims.getId();

            TokenInfo info = store.get(jti);
            if (info == null) return null;

            // 만료 검사
            if (Instant.now().isAfter(info.getExpiry())) {
                store.remove(jti);
                return null;
            }
            // 해시 일치 검사
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
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody();
            store.remove(claims.getId());
        } catch (Exception ignored) {}
    }

    //------------------------------------------------------------------------------//

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
