package io.springsecurity.springsecurity6x.security.service.ott;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class InMemoryCodeStore implements CodeStore {

    private final ConcurrentMap<String, OneTimeToken> store = new ConcurrentHashMap<>();

    @Override
    public void save(String code, OneTimeToken token) {
        store.put(code, token);
    }

    @Override
    public OneTimeToken consume(String code) {
        return store.remove(code);
    }
}
