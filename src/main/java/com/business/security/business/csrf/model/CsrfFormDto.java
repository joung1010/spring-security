package com.business.security.business.csrf.model;

import lombok.*;

/**
 * <b> CsrfFormDto </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-05
 */

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CsrfFormDto {


    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Request {
        private String username;
        private String password;
    }

    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Response {
        private String token;
    }
}
