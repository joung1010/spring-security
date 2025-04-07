package com.business.security.business.authorization;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * <b> AuthorizationPageController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-07
 */

@Slf4j
@Configuration
public class AuthorizationPageController {

    @GetMapping("/")
    public String index(){
        return "index";
    }
}
