package com.business.security.business.endpoint.session;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> SessionIndexController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-01-20
 */

@Slf4j
@RequiredArgsConstructor

@RequestMapping("/session")
@RestController
public class SessionIndexController {



    @GetMapping("/expired")
    public String expired() {
        return "expired";
    }
}
