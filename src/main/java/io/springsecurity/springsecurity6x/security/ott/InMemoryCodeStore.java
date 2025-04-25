package io.springsecurity.springsecurity6x.security.ott;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class InMemoryCodeStore implements CodeStore {

    private final Map<String, String> store = new ConcurrentHashMap<>();

    @Override
    public void save(String code, String token) {
        store.put(code, token);
    }

    @Override
    public String getToken(String code) {
        return store.get(code);
    }

    @Override
    public void remove(String code) {
        store.remove(code);
    }
}
