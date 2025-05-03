package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

/**
 * DSL로 구성된 글로벌 + 각 인증 플로우 설정을 보관하는 모델
 */
public class PlatformConfig {
    private Customizer<HttpSecurity> global;
    private final List<AuthenticationFlowConfig> flows = new ArrayList<>();

    public void setGlobal(Customizer<HttpSecurity> global) {
        this.global = global;
    }
    public Customizer<HttpSecurity> getGlobal() {
        return global;
    }
    public void addFlow(AuthenticationFlowConfig flow) {
        this.flows.add(flow);
    }
    public List<AuthenticationFlowConfig> getFlows() {
        return List.copyOf(flows);
    }
}
