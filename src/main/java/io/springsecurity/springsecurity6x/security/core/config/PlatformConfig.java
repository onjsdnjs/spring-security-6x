package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * DSL로 구성된 글로벌 + 각 인증 플로우 설정을 보관하는 모델
 */
public final class PlatformConfig {
    private final Customizer<HttpSecurity> global;
    private final List<AuthenticationFlowConfig> flows;

    private PlatformConfig(Builder builder) {
        this.global = builder.global;
        this.flows   = List.copyOf(builder.flows);
    }

    public Customizer<HttpSecurity> global() {
        return global;
    }

    public List<AuthenticationFlowConfig> flows() {
        return flows;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Customizer<HttpSecurity> global = http -> {};
        private final List<AuthenticationFlowConfig> flows = new ArrayList<>();

        public Builder global(Customizer<HttpSecurity> global) {
            this.global = global;
            return this;
        }

        public Builder addFlow(AuthenticationFlowConfig flow) {
            this.flows.add(flow);
            return this;
        }

        /**
         * Replace the last added flow, used for setting state immutably
         */
        public Builder replaceLastFlow(AuthenticationFlowConfig flow) {
            if (this.flows.isEmpty()) {
                throw new IllegalStateException("No flow to replace");
            }
            this.flows.removeLast();
            this.flows.add(flow);
            return this;
        }

        public PlatformConfig build() {
            return new PlatformConfig(this);
        }
    }
}
