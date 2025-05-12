package com.business.security.business.endpoint.csrf;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * <b> CsrfPageController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-05
 */

@Slf4j
@Controller
public class CsrfPageController {

    @GetMapping("/form")
    public String form() {
        return "form";
    }

    @GetMapping("cookie")
    public String cookie() {
        return "cookie";
    }

}
