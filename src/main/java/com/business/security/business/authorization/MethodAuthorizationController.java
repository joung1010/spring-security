package com.business.security.business.authorization;

import com.business.security.business.authorization.model.UserAccount;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

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
    public String user(@PathVariable("id") String id) {
        return id;
    }


    @GetMapping("/owner/{id}")
    @PostAuthorize("returnObject.owner == authentication.name")
    public UserAccount getOwner(@PathVariable("id") String id) {

        return UserAccount.builder()
                .owner(id)
                .isSecure(false)
                .build();
    }

    @GetMapping("/secured")
    @PostAuthorize("hasAuthority('ROLE_ADMIN') and returnObject.isSecure")
    public UserAccount getOwnerSecured(String name, String secured) {
         return UserAccount.builder()
                .owner(name)
                    .isSecure("Y".equals(secured))
                .build();
    }


}
