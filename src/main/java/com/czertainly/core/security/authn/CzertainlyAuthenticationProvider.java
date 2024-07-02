package com.czertainly.core.security.authn;

import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CzertainlyAuthenticationProvider implements AuthenticationProvider {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private final CzertainlyAuthenticationClient authClient;

    public CzertainlyAuthenticationProvider(@Autowired CzertainlyAuthenticationClient authClient) {
        this.authClient = authClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CzertainlyAuthenticationRequest authRequest = (CzertainlyAuthenticationRequest) authentication;
        logger.trace("Going to authenticate users against the Czertainly Authentication Service.");
        AuthenticationInfo authInfo = authClient.authenticate(authRequest.getHeaders());

        if(authInfo.isAnonymous()) {
            logger.trace("User not identified, using anonymous.".formatted());
            return new AnonymousAuthenticationToken(UUID.randomUUID().toString(), new CzertainlyUserDetails(authInfo), authInfo.getAuthorities());
        }

        logger.trace("User has been successfully authenticated as '%s'.".formatted(authInfo.getUsername()));
        return new CzertainlyAuthenticationToken(new CzertainlyUserDetails(authInfo));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(CzertainlyAuthenticationRequest.class);
    }
}
