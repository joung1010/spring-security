package com.business.security.business.authorization;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> MethodAuthorizationController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-21
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization1", matchIfMissing = false)

@RequestMapping("/method")
@RestController
public class MethodAuthorizationController {

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String admin() {
        return "admin";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
    public String user() {
        return "user";
    }

    @GetMapping("/is-authenticated")
    @PreAuthorize("isAuthenticated()")
    public String isAuthenticated() {
        return "isAuthenticated";
    }


    @GetMapping("/user/{id}")
    @PreAuthorize("#id == authentication.name")
    public String isAuthenticated(@PathVariable("id") String id) {
        return id;
    }


}
