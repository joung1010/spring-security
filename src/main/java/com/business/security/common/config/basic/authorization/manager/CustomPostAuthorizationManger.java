package com.business.security.common.config.basic.authorization.manager;

import com.business.security.business.endpoint.authorization.model.AccountVo;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

/**
 * <b> CustomPostAuthorizationManger </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-10
 */
public class CustomPostAuthorizationManger implements AuthorizationManager<MethodInvocationResult> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult result) {

        AccountVo accountVo = (AccountVo) result.getResult();
        boolean isGranted = accountVo.getOwner().equals(authentication.get().getName());

        return new AuthorizationDecision(isGranted);
    }
}
