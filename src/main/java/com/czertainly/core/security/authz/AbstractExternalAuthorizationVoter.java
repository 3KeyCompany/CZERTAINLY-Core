package com.czertainly.core.security.authz;

import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public abstract class AbstractExternalAuthorizationVoter<T> implements AccessDecisionVoter<T> {

    protected final Log logger = LogFactory.getLog(this.getClass());

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return (attribute.getAttribute() != null) && (attribute instanceof ExternalAuthorizationConfigAttribute);
    }

    @Override
    public int vote(Authentication authentication, T object, Collection<ConfigAttribute> attributes) {
        if (!(authentication instanceof CzertainlyAuthenticationToken || authentication instanceof AnonymousAuthenticationToken)) {
            logger.trace("Authentication is not of type 'CzertainlyAuthenticationToken' or 'AnonymousAuthenticationToken'. Abstaining from voting.");
            return ACCESS_ABSTAIN;
        }

        if (!canDecide(authentication, object)) {
            logger.trace("Abstaining from voting as voter can't decide for given object.");
            return ACCESS_ABSTAIN;
        }

        if (attributes.stream().noneMatch(this::supports)) {
            logger.trace("No supported config attributes found.");
        }

        if (this.supports(object.getClass())) {
            List<ExternalAuthorizationConfigAttribute> configAttributes = getExternalAuthorizationConfigAttributes(attributes);

            if (authentication instanceof CzertainlyAuthenticationToken token) {
                return voteInternal(token, object, configAttributes);
            } else {
                return voteInternal((AnonymousAuthenticationToken) authentication, object, configAttributes);
            }

        } else {
            logger.warn("Unknown object type '%s'. Abstaining from voting.".formatted(object.getClass().getName()));
            return ACCESS_ABSTAIN;
        }
    }

    protected abstract int voteInternal(CzertainlyAuthenticationToken authentication, T object, List<ExternalAuthorizationConfigAttribute> attributes);

    protected abstract int voteInternal(AnonymousAuthenticationToken authenticationToken, T object, List<ExternalAuthorizationConfigAttribute> attributes);

    protected abstract boolean canDecide(Authentication auth, T object);

    private List<ExternalAuthorizationConfigAttribute> getExternalAuthorizationConfigAttributes(Collection<ConfigAttribute> attributes) {
        return attributes
                .stream()
                .filter(a -> a instanceof ExternalAuthorizationConfigAttribute)
                .map(a -> (ExternalAuthorizationConfigAttribute) a)
                .collect(Collectors.toList());
    }
}
