package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class FlowContextFactory {

    private final FeatureRegistry featureRegistry; // 필요에 따라 주입

    public FlowContextFactory(FeatureRegistry featureRegistry) {
        this.featureRegistry = featureRegistry;
    }

    public List<FlowContext> createAndSortFlows(PlatformConfig config, PlatformContext platformContext) {
        List<FlowContext> flows = new ArrayList<>();
        for (AuthenticationFlowConfig flowCfg : config.flows()) {
            HttpSecurity http = platformContext.newHttp();
            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config);
            platformContext.share(FlowContext.class, fc);
            setupSharedObjects(fc); // 이 메소드는 이 클래스 내부 private 메소드로 이동
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().order()));
        return flows;
    }

    private void setupSharedObjects(FlowContext fc) {
        HttpSecurity http = fc.http();
        http.setSharedObject(ContextPersistence.class, new HttpSessionContextPersistence());
        http.setSharedObject(StateMachineManager.class, new StateMachineManager(fc.flow()));
        List<MfaStateHandler> handlers = List.of(
                new FormStateHandler(), new RestStateHandler(),
                new OttStateHandler(), new PasskeyStateHandler(),
                new RecoveryStateHandler(), new TokenStateHandler()
        );
        http.setSharedObject(StateHandlerRegistry.class, new StateHandlerRegistry(handlers));
        http.setSharedObject(ChallengeRouter.class, new ChallengeRouter(new DefaultChallengeGenerator()));
        http.setSharedObject(FeatureRegistry.class, featureRegistry); // FeatureRegistry 주입 필요
    }
}
