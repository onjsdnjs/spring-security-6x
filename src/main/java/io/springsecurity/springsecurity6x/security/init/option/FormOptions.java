package io.springsecurity.springsecurity6x.security.init.option;

import java.util.List;

public class FormOptions {

    private String loginPage;
    private List<String> matchers;

    public String loginPage() {
        return loginPage;
    }

    public void loginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public List<String> matchers() {
        return matchers;
    }

    public void matchers(List<String> matchers) {
        this.matchers = matchers;
    }
}