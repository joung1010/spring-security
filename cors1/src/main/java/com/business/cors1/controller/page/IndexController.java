package com.business.cors1.controller.page;

import org.springframework.stereotype.Controller;

/**
 * <b> IndexController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-03-24
 */

@Controller
public class IndexController {

    public String index() {
        return "index";
    }
}
