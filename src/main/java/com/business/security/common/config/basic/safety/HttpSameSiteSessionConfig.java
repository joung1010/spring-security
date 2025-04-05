package com.business.security.common.config.basic.safety;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.concurrent.ConcurrentHashMap;

/**
 * <b> HttpSameSiteSessionCofig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-06
 */

@EnableSpringHttpSession
@ConditionalOnProperty(value = "security.type", havingValue = "same-site", matchIfMissing = false)

@Configuration
public class HttpSameSiteSessionConfig {

    @RequiredArgsConstructor
    @Getter
    public static enum HttpSameSite {
        LAX("Lax"), STRICT("Strict"), NONE("None");

        private final String code;
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setUseHttpOnlyCookie(true); //해당 쿠니는 http 통신에 사용
        cookieSerializer.setUseSecureCookie(true);
        cookieSerializer.setSameSite(HttpSameSite.NONE.getCode());

        return cookieSerializer;
    }

    @Bean
    public SessionRepository<MapSession> sessionSessionRepository() {
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }


}
