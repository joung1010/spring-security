package com.business.security.business.endpoint.authorization;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> AuthorityAuthorizationManagerController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-01
 */

@Slf4j

@ConditionalOnProperty(value = "security.type", havingValue = "authorization-custom2", matchIfMissing = false)
@RequestMapping("/custom")
@RestController
public class CustomAuthorizationManagerController {

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/db")
    public String db() {
        return "db";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/secure")
    public String secure() {
        return "secure";
    }
}
