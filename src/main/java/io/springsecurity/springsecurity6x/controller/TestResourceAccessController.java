package io.springsecurity.springsecurity6x.controller;


import io.springsecurity.springsecurity6x.service.ResourceAccessService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestResourceAccessController {

    private final ResourceAccessService resourceAccessService;

    public TestResourceAccessController(ResourceAccessService resourceAccessService) {
        this.resourceAccessService = resourceAccessService;
    }

    @GetMapping("/test/call-secure-api")
    public String callSecureApi() {
        return resourceAccessService.callSecureApi();
    }
}

