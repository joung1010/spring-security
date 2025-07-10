package com.business.security.business.endpoint.authorization;

import com.business.security.business.endpoint.authorization.model.AccountVo;
import com.business.security.business.service.authorization.method.CustomPointCutDataService;
import com.business.security.business.service.authorization.method.PointCutDataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization7", matchIfMissing = false)

@RequiredArgsConstructor
@RestController
public class MethodAuthorization7Controller {

    private final CustomPointCutDataService service;


    @GetMapping("/method-user")
    public String user() {
        return this.service.getUser();
    }

    @GetMapping("/method-owner")
    public AccountVo admin(String name) {
        return this.service.getOwner(name);
    }

    @GetMapping("/method-display")
    public String permitAll() {
        return this.service.display();
    }


}
