package com.business.security.business.endpoint.event;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> AuthenticationEventController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-14
 */

@ConditionalOnProperty(value = "security.type", havingValue = "event-2", matchIfMissing = false)

@RequestMapping("/events")
@RestController
public class AuthenticationEventController2 {

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/db")
    public String db(){
        return "db";
    }
    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }
}
