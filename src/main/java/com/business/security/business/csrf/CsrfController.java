package com.business.security.business.csrf;

import com.business.security.business.csrf.model.CsrfFormDto;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

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

    @GetMapping("/csrf-token")
    public String csrfToken(HttpServletRequest request) {
        CsrfToken csrfToken1 = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken2 = (CsrfToken) request.getAttribute("_csrf");
        String token = csrfToken1.getToken();

        return token;
    }

    @PostMapping("/formCsrf")
    public CsrfFormDto.Response formCsrf(@ModelAttribute CsrfFormDto.Request request,
                                         @RequestAttribute(name = "_csrf", required = false) CsrfToken csrfToken) {
        return CsrfFormDto.Response.builder()
                .token(csrfToken.getToken())
                .build();
    }
    @PostMapping("/cookieCsrf")
    public CsrfToken cookieCsrf( CsrfToken csrfToken) {
        return csrfToken;
    }
}
