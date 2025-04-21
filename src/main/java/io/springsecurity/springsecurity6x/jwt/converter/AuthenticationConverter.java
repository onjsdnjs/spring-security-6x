package io.springsecurity.springsecurity6x.jwt.converter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.security.Key;

public interface AuthenticationConverter {
     UsernamePasswordAuthenticationToken getAuthentication(String token);
}
