package io.springsecurity.springsecurity6x.security.converter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public interface AuthenticationConverter {
     UsernamePasswordAuthenticationToken getAuthentication(String token);
}
