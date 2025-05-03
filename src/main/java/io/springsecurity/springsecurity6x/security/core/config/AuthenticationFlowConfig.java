package io.springsecurity.springsecurity6x.security.core.config;

import java.util.List;

public class AuthenticationFlowConfig {
    private final String flowId;
    private final List<AuthenticationStepConfig> steps;
    private StateConfig state;

    public AuthenticationFlowConfig(String flowId, List<AuthenticationStepConfig> steps, StateConfig state) {
        this.flowId = flowId;
        this.steps = steps;
        this.state = state;
    }

    public String getFlowId() {
        return flowId;
    }

    public List<AuthenticationStepConfig> getSteps() {
        return steps;
    }

    public StateConfig getState() {
        return state;
    }

    public void setState(StateConfig state) {
        this.state = state;
    }
}
