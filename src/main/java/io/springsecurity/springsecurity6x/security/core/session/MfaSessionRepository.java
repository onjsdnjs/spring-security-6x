package io.springsecurity.springsecurity6x.security.core.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

import java.time.Duration;

/**
 * MFA 세션 관리를 위한 Repository 인터페이스
 * - HTTP Session, Redis, 기타 저장소에 대한 추상화
 * - 설정에 따라 구현체 선택 가능
 */
public interface MfaSessionRepository {

    /**
     * MFA 세션 ID 저장
     * @param sessionId MFA 세션 ID
     * @param request HTTP 요청
     * @param response HTTP 응답 (쿠키 설정용, null 가능)
     */
    void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    /**
     * 요청에서 MFA 세션 ID 조회
     * @param request HTTP 요청
     * @return MFA 세션 ID (없으면 null)
     */
    @Nullable
    String getSessionId(HttpServletRequest request);

    /**
     * MFA 세션 제거
     * @param sessionId MFA 세션 ID
     * @param request HTTP 요청
     * @param response HTTP 응답 (쿠키 무효화용, null 가능)
     */
    void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    /**
     * 세션 활동 갱신 (TTL 연장 등)
     * @param sessionId MFA 세션 ID
     */
    void refreshSession(String sessionId);

    /**
     * 세션 존재 여부 확인
     * @param sessionId MFA 세션 ID
     * @return 존재하면 true
     */
    boolean existsSession(String sessionId);

    /**
     * 세션 타임아웃 설정
     * @param timeout 타임아웃 기간
     */
    void setSessionTimeout(Duration timeout);

    /**
     * Repository 타입 반환 (디버깅/로깅용)
     * @return Repository 타입명
     */
    String getRepositoryType();
}