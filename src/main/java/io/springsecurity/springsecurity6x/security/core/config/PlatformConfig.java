package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

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
        flows.add(flow);
    }

    public List<AuthenticationFlowConfig> getFlows() {
        return flows;
    }
}
