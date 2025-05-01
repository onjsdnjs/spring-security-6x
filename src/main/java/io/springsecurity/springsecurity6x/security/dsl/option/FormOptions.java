package io.springsecurity.springsecurity6x.security.dsl.option;

import lombok.Data;

import java.util.List;

@Data
public class FormOptions {
    private String loginPage;
    private List<String> matchers;
}