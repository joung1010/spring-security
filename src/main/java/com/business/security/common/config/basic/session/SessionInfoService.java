package com.business.security.common.config.basic.session;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * <b> SessionInfoService </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-02-03
 */
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(value = "security.type", havingValue = "session", matchIfMissing = false)

@Service
public class SessionInfoService {

    private final SessionRegistry sessionRegistry;

    public void sessionInfo() {
        List<Object> allPrincipals = sessionRegistry.getAllPrincipals();
        for (Object principal : allPrincipals) {
            List<SessionInformation> allSessions = sessionRegistry.getAllSessions(principal, false);
            for (SessionInformation session : allSessions) {
                log.info("사용자 {}, 세션ID {}, 최종 요청시간 {}", principal, session.getSessionId(), session.getLastRequest());
            }

        }
    }
}
