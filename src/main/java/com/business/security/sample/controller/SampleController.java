package com.business.security.sample.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b>  </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-07-04
 */

@Slf4j
@RequestMapping("/sample")
@RestController
public class SampleController {

    @GetMapping("/health-check")
    public String healthCheck() {
        return "OK";
    }
}
