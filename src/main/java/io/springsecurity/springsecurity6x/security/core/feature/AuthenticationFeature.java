package io.springsecurity.springsecurity6x.security.core.feature;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 개별 인증 단계(예: Form 로그인, REST 로그인, Passkey, OTT 등)의
 * HttpSecurity 구성 로직을 캡슐화한 기능 인터페이스입니다.
 *
 * 각 구현체는 자신의 인증 방식에 맞추어
 * HttpSecurity에 필터 추가, 엔드포인트 설정, 핸들러 지정 등을 수행합니다.
 */
public interface AuthenticationFeature {

    /**
     * 이 인증 기능의 고유 식별자(ID)를 반환합니다.
     * 보통 DSL 에서 지정한 타입("form", "rest", "passkey", "ott", "mfa")과 매핑됩니다.
     *
     * @return 인증 기능 ID
     */
    String getId();

    int getOrder();

    /**
     * 주어진 HttpSecurity 및 PlatformContext를 사용하여
     * 자신의 인증 단계 설정을 적용합니다.
     *
     * @param http  HttpSecurity 빌더
     * @param ctx   PlatformContext (공유 객체 접근, 체인 등록 지원 등)
     * @throws Exception 구성 중 오류 발생 시
     */
    void apply(HttpSecurity http, PlatformContext ctx) throws Exception;
}

