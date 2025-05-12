package com.business.security.business.endpoint.authorization;

import com.business.security.business.endpoint.authorization.model.AccountVo;
import com.business.security.business.service.authorization.DataService;
import com.business.security.business.service.authorization.method.annotations.IsAdmin;
import com.business.security.business.service.authorization.method.annotations.OwnerShip;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * <b> MethodAuthorization2Controller </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization3", matchIfMissing = false)

@RequiredArgsConstructor
@RestController
public class MethodAuthorization3Controller {


    @GetMapping("/method-user")
    @Secured("ROLE_USER")
    public String user() {
        return "user";
    }

    @GetMapping("/method-admin")
    @RolesAllowed("ADMIN")
    public String admin() {
        return "admin";
    }

    @GetMapping("/method-permitAll")
    @PermitAll
    public String permitAll() {
        return "permitAll";
    }


    @GetMapping("/method-denyAll")
    @DenyAll
    public String denyAll() {
        log.info("denyAll");
        return "denyAll";
    }


    @GetMapping("/method-isAdmin")
    @IsAdmin
    public String isAdmin() {
        return "isAdmin";
    }

    @GetMapping("/method-owner")
    @OwnerShip
    public AccountVo owner(String name) {
        return new AccountVo(name,false);
    }

    @GetMapping("/delete")
    @PreAuthorize("@myAuthorization.isUser(#root)")
    public String delete(String name) {
        return "delete";
    }
}
