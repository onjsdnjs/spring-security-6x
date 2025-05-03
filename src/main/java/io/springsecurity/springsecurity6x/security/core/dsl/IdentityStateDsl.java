package io.springsecurity.springsecurity6x.security.core.dsl;

/**
 * 인증 방식 설정 후 호출되는 DSL로,
 * 인증 후 사용할 상태 관리 전략을 선택하는 단계입니다.
 */
public interface IdentityStateDsl {

    /**
     * 세션 기반 상태 유지 전략을 사용합니다.
     *
     * @return 상위 DSL 으로 복귀
     */
    SecurityPlatformDsl session();

    /**
     * 외부 JWT 라이브러리 기반 토큰 전략을 사용합니다.
     *
     * @return 상위 DSL 으로 복귀
     */
    SecurityPlatformDsl jwt();

    /**
     * Spring AuthorizationServer/ResourceServer(OAuth2) 기반 JWT 전략을 사용합니다.
     *
     * @return 상위 DSL 으로 복귀
     */
    SecurityPlatformDsl oauth2();
}

