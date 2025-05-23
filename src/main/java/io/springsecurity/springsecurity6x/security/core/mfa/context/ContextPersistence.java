package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;

/**
 * MFA 컨텍스트 영속화 인터페이스
 */
public interface ContextPersistence {

    /**
     * HttpServletRequest에서 FactorContext 로드
     */
    @Nullable
    FactorContext contextLoad(HttpServletRequest request);

    /**
     * 세션 ID로 FactorContext 로드
     */
    @Nullable
    default FactorContext loadContext(String sessionId, HttpServletRequest request) {
        // 기본 구현: contextLoad 메서드 호출
        return contextLoad(request);
    }

    /**
     * FactorContext 저장
     */
    void saveContext(@Nullable FactorContext ctx, HttpServletRequest request);

    /**
     * FactorContext 삭제
     */
    void deleteContext(HttpServletRequest request);
}