package io.springsecurity.springsecurity6x.security.dsl.option;

import lombok.Data;

import java.util.List;

@Data
public class OttOptions {
    private String loginProcessingUrl;
    private List<String> matchers;
}