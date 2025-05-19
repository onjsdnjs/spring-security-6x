package io.springsecurity.springsecurity6x.security.core.asep.dsl;

import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class FormAsepAttributes implements BaseAsepAttributes {
    private final List<SecurityHandlerMethodArgumentResolver> customArgumentResolvers = new ArrayList<>();
    private final List<SecurityHandlerMethodReturnValueHandler> customReturnValueHandlers = new ArrayList<>();

    public FormAsepAttributes() {
        // 기본 생성자
    }

    public FormAsepAttributes exceptionArgumentResolver(SecurityHandlerMethodArgumentResolver resolver) {
        this.customArgumentResolvers.add(Objects.requireNonNull(resolver, "resolver cannot be null"));
        return this;
    }

    public FormAsepAttributes exceptionArgumentResolvers(List<SecurityHandlerMethodArgumentResolver> resolvers) {
        this.customArgumentResolvers.addAll(Objects.requireNonNull(resolvers, "resolvers cannot be null"));
        return this;
    }

    public FormAsepAttributes exceptionReturnValueHandler(SecurityHandlerMethodReturnValueHandler handler) {
        this.customReturnValueHandlers.add(Objects.requireNonNull(handler, "handler cannot be null"));
        return this;
    }

    public FormAsepAttributes exceptionReturnValueHandlers(List<SecurityHandlerMethodReturnValueHandler> handlers) {
        this.customReturnValueHandlers.addAll(Objects.requireNonNull(handlers, "handlers cannot be null"));
        return this;
    }

    @Override
    public List<SecurityHandlerMethodArgumentResolver> getCustomArgumentResolvers() {
        return Collections.unmodifiableList(customArgumentResolvers);
    }

    @Override
    public List<SecurityHandlerMethodReturnValueHandler> getCustomReturnValueHandlers() {
        return Collections.unmodifiableList(customReturnValueHandlers);
    }
}
