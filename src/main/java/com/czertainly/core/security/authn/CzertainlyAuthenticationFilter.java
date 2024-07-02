package com.czertainly.core.security.authn;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CzertainlyAuthenticationFilter extends OncePerRequestFilter {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private final AuthenticationManager authenticationManager;

    private final CzertainlyAuthenticationConverter authenticationConverter;

    private final String healthCheckRequest;


    public CzertainlyAuthenticationFilter(final AuthenticationManager authenticationManager, final CzertainlyAuthenticationConverter authenticationConverter, final String restApiPrefix) {
        this.authenticationManager = authenticationManager;
        this.authenticationConverter = authenticationConverter;
        this.healthCheckRequest = "/api" + restApiPrefix + "health";
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (isAuthenticationNeeded(request)) {
            logger.trace("Going to authenticate the '%s' request on '%s'.".formatted(request.getMethod(), request.getRequestURI()));
            CzertainlyAuthenticationRequest authRequest = this.authenticationConverter.convert(request);

            try {
                Authentication authResult = this.authenticationManager.authenticate(authRequest);

                logger.trace("Authentication result: %s".formatted(authResult.isAuthenticated() ? "authenticated" : "unauthenticated"));

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authResult);
                SecurityContextHolder.setContext(context);
            } catch (AuthenticationException e) {
                logger.info("Failed to authenticate user.");
                logger.debug("Failed to authenticate user.", e);
                SecurityContextHolder.clearContext();
            }
        } else {
            logger.trace("The user is already authenticated. Will not re-authenticate");
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAuthenticationNeeded(final HttpServletRequest request) {

        if (request.getRequestURI().startsWith(healthCheckRequest)) {
            logger.debug("Actuator health checks are automatically authenticated.");
            return false;
        }

        SecurityContext context = SecurityContextHolder.getContext();
        if (context == null) {
            return true;
        }
        Authentication auth = context.getAuthentication();

        if (auth == null) {
            return true;
        }

        return !auth.isAuthenticated();
    }

}

