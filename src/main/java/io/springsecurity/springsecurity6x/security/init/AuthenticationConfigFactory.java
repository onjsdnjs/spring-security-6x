package io.springsecurity.springsecurity6x.security.init;

import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;

/**
 * 인증 방식, 옵션, 상태 전략 정보를 기반으로 AuthenticationConfig 객체를 생성하는 팩토리 클래스.
 */
public class AuthenticationConfigFactory {

    public static <T> AuthenticationConfig create(AuthType type, T options, StateType stateType, Customizer<T> customizer) {
        return new AuthenticationConfig(type.name().toLowerCase(), options, stateType.name().toLowerCase(), customizer);
    }
}
