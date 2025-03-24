package com.business.security.business.csrf;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> CsrfController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-03-24
 */

@Slf4j
@RestController
public class CsrfController {

    @PostMapping("/csrf")
    public String csrf() {
        return "CSRF 적용됨";
    }

    @PostMapping("/csrf-ignore")
    public String csrfIgnore() {
        return "CSRF 적용됨";
    }
}
