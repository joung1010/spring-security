package com.business.security.business.authentication.mvc;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> MvcBaseController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-01-14
 */

@RequestMapping("/mvc")
@RestController
public class MvcBaseController {

    @GetMapping("/index")
    public Authentication index(Authentication authentication){
        return authentication;
    }
}
