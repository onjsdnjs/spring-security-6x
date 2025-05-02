package io.springsecurity.springsecurity6x.security.init;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * DSL로부터 수집된 AuthenticationConfig 객체를 관리하는 설정 저장소.
 */
public class IdentityConfig {

    private final List<AuthenticationConfig> authentications = new ArrayList<>();

    public void add(AuthenticationConfig config) {
        authentications.add(config);
    }

    public List<AuthenticationConfig> getAuthentications() {
        return Collections.unmodifiableList(authentications);
    }
}


