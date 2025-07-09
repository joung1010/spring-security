package com.business.security.business.endpoint.authorization;

import com.business.security.business.endpoint.authorization.model.AccountVo;
import com.business.security.business.service.authorization.method.MethodAuthorizationDataService;
import com.business.security.business.service.authorization.method.annotations.IsAdmin;
import com.business.security.business.service.authorization.method.annotations.OwnerShip;
import com.business.security.business.service.authorization.method.model.vo.Account4Vo;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> MethodAuthorization2Controller </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization4", matchIfMissing = false)

@RequiredArgsConstructor
@RestController
public class MethodAuthorization4Controller {

    private final MethodAuthorizationDataService service;


    @GetMapping("/method-user")
    @Secured("ROLE_USER")
    public String user() {
        return this.service.getUser();
    }

    @GetMapping("/method-owner")
    @RolesAllowed("ADMIN")
    public Account4Vo admin(String name) {
        return this.service.getOwner(name);
    }

    @GetMapping("/method-display")
    @PermitAll
    public String permitAll() {
        return this.service.display();
    }


}
