package com.business.security.common.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * <b>  </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-07-15
 */

@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityConfigBasic {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Basic Security Filter Chain Setting =============");

        http.authorizeRequests(auth -> auth.anyRequest().authenticated()) // 모든 요청에 대해 인증을 요구합니다.
                .formLogin(Customizer.withDefaults()); // 기본 폼 로그인을 활성화합니다.

        log.info("Basic Security Filter Chain Setting End =============");
        return http.build();
    }
}
