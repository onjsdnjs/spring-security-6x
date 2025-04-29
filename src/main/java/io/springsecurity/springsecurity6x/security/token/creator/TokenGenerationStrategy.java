package io.springsecurity.springsecurity6x.security.token.creator;

import io.springsecurity.springsecurity6x.security.enums.TokenType;
import org.springframework.security.core.Authentication;

public interface TokenGenerationStrategy {
    TokenType getType();
    String generate(Authentication authentication);
}

