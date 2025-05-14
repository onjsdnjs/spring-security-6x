package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;

import java.util.List;

public interface SecurityConfigurerProvider {
    List<SecurityConfigurer> getConfigurers(PlatformContext platformContext, PlatformConfig platformConfig);
}
