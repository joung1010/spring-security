package com.business.security.common.config.basic.logout;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

/**
 * <b> SecurityAnonymousConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-08-20
 */

@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityLogoutConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .logout(logout -> logout
//                        .logoutUrl("/logoutProc")
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc","POST"))
                        .logoutSuccessUrl("/logoutSuccess")
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request
                                    , HttpServletResponse response
                                    , Authentication authentication) throws IOException, ServletException {

                                response.sendRedirect("/logoutSuccess");
                            }
                        })
                        .deleteCookies("JSESSIONID","remember-me")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request
                                    , HttpServletResponse response
                                    , Authentication authentication) {

                                request.getSession().invalidate(); // 세션 무효
                                SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null); // 인증 삭제
                                SecurityContextHolder.getContextHolderStrategy().clearContext();


                            }
                        })
                        .permitAll()
                );


        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }
}
