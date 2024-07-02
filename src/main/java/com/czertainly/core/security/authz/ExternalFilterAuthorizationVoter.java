package com.czertainly.core.security.authz;

import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authz.opa.OpaClient;
import com.czertainly.core.security.authz.opa.dto.AnonymousPrincipal;
import com.czertainly.core.security.authz.opa.dto.OpaRequestDetails;
import com.czertainly.core.security.authz.opa.dto.OpaRequestedResource;
import com.czertainly.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class ExternalFilterAuthorizationVoter extends AbstractExternalAuthorizationVoter<FilterInvocation> {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private final OpaClient opaClient;

    private final ObjectMapper om;

    private RequestMatcher toAuthorizeRequestsMatcher;

    private RequestMatcher doNotAuthorizeAnonymousRequestsMatcher;

    public ExternalFilterAuthorizationVoter(@Autowired OpaClient opaClient, @Autowired ObjectMapper om) {
        this.opaClient = opaClient;
        this.om = om;
    }

    @Override
    public boolean supports(Class clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    protected int voteInternal(CzertainlyAuthenticationToken authentication, FilterInvocation fi, List<ExternalAuthorizationConfigAttribute> attributes) {
        OpaRequestDetails opaDetails = null;
        if (authentication.getDetails() instanceof WebAuthenticationDetails) {
            String remoteAddress = ((WebAuthenticationDetails) authentication.getDetails()).getRemoteAddress();
            opaDetails = new OpaRequestDetails(remoteAddress);
        }
        return this.vote(authentication.getPrincipal().getRawData(), fi, opaDetails);
    }

    @Override
    protected int voteInternal(AnonymousAuthenticationToken authentication, FilterInvocation fi, List<ExternalAuthorizationConfigAttribute> attributes) {
        OpaRequestDetails opaDetails = null;
        if (authentication.getDetails() instanceof WebAuthenticationDetails) {
            String remoteAddress = ((WebAuthenticationDetails) authentication.getDetails()).getRemoteAddress();
            opaDetails = new OpaRequestDetails(remoteAddress);
        }
        try {
            return this.vote(om.writeValueAsString(new AnonymousPrincipal(authentication.getName())), fi, opaDetails);
        } catch (JsonProcessingException e) {
            logger.error("An error occurred during voting. Access will be denied.", e);
            return ACCESS_DENIED;
        }
    }

    private int vote(String principal, FilterInvocation fi, OpaRequestDetails details) {
        try {
            List<String> urlParts = Arrays.stream(fi.getRequestUrl()
                            .split("/"))
                    .filter(p -> !p.isBlank())
                    .collect(Collectors.toList());

            OpaRequestedResource resource = new OpaRequestedResource(urlParts);


            OpaResourceAccessResult result = this.checkAccess(principal, resource, details);
            if (result.isAuthorized()) {
                logger.trace(
                        String.format(
                                "Access to the endpoint '%s' has been granted by the following rules [%s].",
                                fi.getRequestUrl(),
                                String.join(",", result.getAllow())
                        )
                );
                return ACCESS_GRANTED;
            } else {
                logger.trace(String.format("Access to the endpoint '%s' has been denied.", fi.getRequestUrl()));
                return ACCESS_DENIED;
            }
        } catch (Exception e) {
            logger.error(String.format("Unable verify access to the endpoint '%s'. Voting to deny access.", fi.getRequestUrl()), e);
            return ACCESS_DENIED;
        }
    }

    @Override
    protected boolean canDecide(Authentication auth, FilterInvocation fi) {
        if (auth instanceof AnonymousAuthenticationToken) {
            // First to verify that the request was not explicitly excluded from the voting
            boolean doNotAuthorize = doNotAuthorizeAnonymousRequestsMatcher != null && this.doNotAuthorizeAnonymousRequestsMatcher.matches(fi.getRequest());
            if (doNotAuthorize) {
                logger.trace("Voter is set not to decide for the " + fi);
                return false;
            }

            // For security reasons, we want to authorize all anonymous requests except those that were excluded in step one
            logger.trace("Will vote because the request is authenticated as anonymous.");
            return true;
        }

        // Finally, check if non-anonymous request should be authorized
        boolean shouldAuthorize = toAuthorizeRequestsMatcher == null || this.toAuthorizeRequestsMatcher.matches(fi.getRequest());
        if (!shouldAuthorize) {
            logger.trace("Voter can't decide for the " + fi);
        }

        return shouldAuthorize;
    }

    protected OpaResourceAccessResult checkAccess(String principal, OpaRequestedResource resource, OpaRequestDetails opaDetails) {
        try {
            return this.opaClient.checkResourceAccess(OpaPolicy.ENDPOINT.policyName, resource, principal, opaDetails);
        } catch (Exception e) {
            logger.error(
                    
                            "An error occurred during the authorization request to the OPA policy '%s'.".formatted(
                            OpaPolicy.ENDPOINT.policyName),
                    e
            );
            return OpaResourceAccessResult.unauthorized();
        }
    }

    public void setToAuthorizeRequestsMatcher(RequestMatcher toAuthorizeRequestsMatcher) {
        this.toAuthorizeRequestsMatcher = toAuthorizeRequestsMatcher;
    }

    public void setDoNotAuthorizeAnonymousRequestsMatcher(RequestMatcher doNotAuthorizeRequestsMatcher) {
        this.doNotAuthorizeAnonymousRequestsMatcher = doNotAuthorizeRequestsMatcher;
    }
}
