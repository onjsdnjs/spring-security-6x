package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;

/**
 * ContextPersistence 기본 인터페이스 (기존 호환성 유지)
 */
public interface ContextPersistence {

    /**
     * HttpServletRequest 에서 FactorContext 로드
     */
    @Nullable
    FactorContext contextLoad(HttpServletRequest request);

    /**
     * 세션 ID로 FactorContext 로드
     */
    @Nullable
    default FactorContext loadContext(String sessionId, HttpServletRequest request) {
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