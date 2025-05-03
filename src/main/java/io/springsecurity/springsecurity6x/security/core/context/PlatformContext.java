package io.springsecurity.springsecurity6x.security.core.context;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import java.util.Map;

public interface PlatformContext {

    HttpSecurity createBuilder(String chainId) throws Exception;

    void registerChain(String chainId, SecurityFilterChain chain);

    <T> void putShared(Class<T> key, T instance);

    <T> T getShared(Class<T> key);

    Map<Class<?>, Object> getAllShared();
}
