package io.springsecurity.springsecurity6x.security.ott;

import org.springframework.security.authentication.ott.OneTimeToken;

public interface CodeStore {
    void save(String code, OneTimeToken oneTimeToken);
    String getToken(String code);
    void remove(String code);
}
