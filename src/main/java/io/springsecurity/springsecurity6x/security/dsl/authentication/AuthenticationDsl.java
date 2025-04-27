package io.springsecurity.springsecurity6x.security.dsl.authentication;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface AuthenticationDsl {

     void init(HttpSecurity http);
}
