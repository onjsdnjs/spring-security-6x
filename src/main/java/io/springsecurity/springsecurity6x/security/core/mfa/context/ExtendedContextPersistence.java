package io.springsecurity.springsecurity6x.security.core.mfa.context;

/**
 * 확장된 ContextPersistence 인터페이스
 */
public interface ExtendedContextPersistence extends ContextPersistence {

    /**
     * 세션 ID로 직접 삭제
     */
    void deleteContext(String sessionId);

    /**
     * 컨텍스트 존재 여부 확인
     */
    boolean exists(String sessionId);

    /**
     * 컨텍스트 TTL 갱신
     */
    void refreshTtl(String sessionId);

    /**
     * 현재 저장소 타입 반환
     */
    PersistenceType getPersistenceType();

    enum PersistenceType {
        SESSION("HttpSession 기반 저장"),
        REDIS("Redis 분산 저장"),
        STATE_MACHINE("State Machine 통합 저장");

        private final String description;

        PersistenceType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}