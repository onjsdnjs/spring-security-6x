package io.springsecurity.springsecurity6x.jwt;

import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, String> store = new ConcurrentHashMap<>();

    @Override
    public void store(String refreshToken, String username) {
        store.put(refreshToken, username);
    }

    @Override
    public String getUsername(String refreshToken) {
        return store.get(refreshToken);
    }

    @Override
    public void remove(String refreshToken) {
        store.remove(refreshToken);
    }
}
