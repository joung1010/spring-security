package com.business.security.business.endpoint.basic;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * <b> ViewController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Controller
public class ViewController {
    @GetMapping("/method")
    public String method() {
        return "method";
    }
}
