package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FormLoginAsepSettings {
    private final List<SecurityHandlerMethodArgumentResolver> customArgumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> customReturnValueHandlers;

    public FormLoginAsepSettings(List<SecurityHandlerMethodArgumentResolver> customArgumentResolvers,
                                 List<SecurityHandlerMethodReturnValueHandler> customReturnValueHandlers) {
        this.customArgumentResolvers = customArgumentResolvers != null ? new ArrayList<>(customArgumentResolvers) : Collections.emptyList();
        this.customReturnValueHandlers = customReturnValueHandlers != null ? new ArrayList<>(customReturnValueHandlers) : Collections.emptyList();
    }

    public List<SecurityHandlerMethodArgumentResolver> getCustomArgumentResolvers() {
        return Collections.unmodifiableList(customArgumentResolvers);
    }

    public List<SecurityHandlerMethodReturnValueHandler> getCustomReturnValueHandlers() {
        return Collections.unmodifiableList(customReturnValueHandlers);
    }
}
