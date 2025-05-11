package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 각 핸들러가 상속해 사용할 수 있는 추상 클래스.
 * - getOptions(cfg)로 DSL 옵션 획득
 * - before/after 훅 기본 구현 제공
 */
public abstract class AbstractMfaFactorHandler<O> implements MfaFactorHandler {
    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected O getOptions(AuthenticationStepConfig cfg) {
        return (O) cfg.options().get("_options");
    }

    @Override public void beforeAuthentication(FactorContext ctx, AuthenticationStepConfig cfg) throws Exception { }
    @Override public void onSuccess(FactorContext ctx, AuthenticationStepConfig cfg, FactorResult result) throws Exception { }
    @Override public void onFailure(FactorContext ctx, AuthenticationStepConfig cfg, FactorResult result) throws Exception { }
    @Override public void onRetry(FactorContext ctx, AuthenticationStepConfig cfg, int attempt) throws Exception { }
    @Override public void onFinally(FactorContext ctx, AuthenticationStepConfig cfg) throws Exception { }
}

