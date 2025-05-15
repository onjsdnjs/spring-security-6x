package io.springsecurity.springsecurity6x.security.core.config;


import lombok.Getter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Getter
public final class PlatformConfig {
    private final Customizer<HttpSecurity> globalCustomizer; // 이름 변경 (global -> globalCustomizer)
    private final List<AuthenticationFlowConfig> flows;

    private PlatformConfig(Builder builder) {
        this.globalCustomizer = builder.globalCustomizer;
        this.flows = Collections.unmodifiableList(new ArrayList<>(builder.flows)); // 방어적 복사
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Customizer<HttpSecurity> globalCustomizer = http -> {}; // 이름 변경 및 기본값 설정
        private final List<AuthenticationFlowConfig> flows = new ArrayList<>();

        public Builder global(Customizer<HttpSecurity> globalCustomizer) { // 파라미터 이름 변경
            this.globalCustomizer = globalCustomizer;
            return this;
        }

        public Builder addFlow(AuthenticationFlowConfig flow) {
            this.flows.add(flow);
            return this;
        }

        public Builder replaceLastFlow(AuthenticationFlowConfig flow) {
            if (this.flows.isEmpty()) {
                throw new IllegalStateException("No flow to replace");
            }
            this.flows.set(this.flows.size() - 1, flow); // removeLast + add 대신 set 사용
            return this;
        }

        public PlatformConfig build() {
            return new PlatformConfig(this);
        }
    }
}
