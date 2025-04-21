package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.enums.TokenType;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import io.springsecurity.springsecurity6x.jwt.strategy.ExternalTokenSecurityStrategy;
import io.springsecurity.springsecurity6x.jwt.strategy.InternalTokenSecurityStrategy;
import io.springsecurity.springsecurity6x.jwt.strategy.TokenSecurityStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class TokenSecurityStrategyConfigurer {

    private final Map<TokenType, TokenSecurityStrategy> strategies;
    private final IntegrationAuthProperties props;

    public TokenSecurityStrategyConfigurer(List<TokenSecurityStrategy> strategies,
                                           IntegrationAuthProperties integrationAuthProperties) {
        this.strategies = strategies.stream()
                .collect(Collectors.toMap(this::resolveType, Function.identity()));
        this.props = integrationAuthProperties;
    }

    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        TokenType type = props.getTokenType();
        return strategies.get(type).configure(http);
    }

    private TokenType resolveType(TokenSecurityStrategy strategy) {
        if (strategy instanceof ExternalTokenSecurityStrategy) return TokenType.EXTERNAL;
        if (strategy instanceof InternalTokenSecurityStrategy) return TokenType.INTERNAL;
        return TokenType.EXTERNAL;
    }
}

