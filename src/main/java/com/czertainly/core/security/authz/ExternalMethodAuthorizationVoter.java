package com.czertainly.core.security.authz;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.GroupAssociation;
import com.czertainly.core.dao.repository.GroupAssociationRepository;
import com.czertainly.core.dao.repository.OwnerAssociationRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authn.CzertainlyUserDetails;
import com.czertainly.core.security.authz.opa.OpaClient;
import com.czertainly.core.security.authz.opa.dto.AnonymousPrincipal;
import com.czertainly.core.security.authz.opa.dto.OpaRequestDetails;
import com.czertainly.core.security.authz.opa.dto.OpaRequestedResource;
import com.czertainly.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class ExternalMethodAuthorizationVoter extends AbstractExternalAuthorizationVoter<MethodInvocation> {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private static final String NAME_PROP_NAME = "name";
    private static final String ACTION_PROP_NAME = "action";
    private static final String PARENT_NAME_PROP_NAME = "parentName";
    private static final String PARENT_ACTION_PROP_NAME = "parentAction";

    private final OpaClient opaClient;

    private final ObjectMapper om;

    private final GroupAssociationRepository groupAssociationRepository;
    private final OwnerAssociationRepository ownerAssociationRepository;

    public ExternalMethodAuthorizationVoter(@Autowired OpaClient opaClient, @Autowired ObjectMapper om, @Autowired GroupAssociationRepository groupAssociationRepository, @Autowired OwnerAssociationRepository ownerAssociationRepository) {
        this.opaClient = opaClient;
        this.om = om;
        this.groupAssociationRepository = groupAssociationRepository;
        this.ownerAssociationRepository = ownerAssociationRepository;
    }

    @Override
    public boolean supports(Class clazz) {
        return MethodInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    protected int voteInternal(CzertainlyAuthenticationToken auth, MethodInvocation methodInvocation, List<ExternalAuthorizationConfigAttribute> attributes) {
        int result = this.vote(auth.getPrincipal().getRawData(), methodInvocation, attributes);
        if (result == ACCESS_DENIED) {
            return voteGroupOwnerAssociations(auth.getPrincipal(), methodInvocation, attributes);
        }
        return result;
    }

    @Override
    protected int voteInternal(AnonymousAuthenticationToken authenticationToken, MethodInvocation methodInvocation, List<ExternalAuthorizationConfigAttribute> attributes) {
        try {
            return this.vote(om.writeValueAsString(new AnonymousPrincipal(authenticationToken.getName())), methodInvocation, attributes);
        } catch (JsonProcessingException e) {
            logger.error("An error occurred during voting. Access will be denied.", e);
            return ACCESS_DENIED;
        }
    }

    private int voteGroupOwnerAssociations(CzertainlyUserDetails principal, MethodInvocation methodInvocation, List<ExternalAuthorizationConfigAttribute> attributes) {
        Map<String, String> properties = attributes
                .stream()
                .filter(this::shouldBeSendToOpa)
                .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::getAttributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));

        Resource resource;
        ResourceAction resourceAction;
        try {
            resource = Resource.findByCode(properties.get(NAME_PROP_NAME));
            resourceAction = ResourceAction.findByCode(properties.get(ACTION_PROP_NAME));
        } catch (ValidationException e) {
            logger.trace("Unsupported resource or action: " + e.getMessage());
            return ACCESS_DENIED;
        }

        // UUIDs of objects the operation is executed on
        List<SecuredUUID> objectUUIDs = extractUUIDsFromMethodArguments(methodInvocation);
        boolean hasSecurityFilter = hasSecurityFilterParam(methodInvocation);

        // skip if no object UUIDs provided and it is not listing with security filter - cannot evaluate its group and owner associations
        // skip if no owner associations and no group associations (or in case groups only LIST and DETAIL action is allowed through group members permissions)
        if ((objectUUIDs.isEmpty() && !hasSecurityFilter) || (!resource.hasOwner() && (!resource.hasGroups() || (resourceAction != ResourceAction.LIST && resourceAction != ResourceAction.DETAIL)))) {
            return ACCESS_DENIED;
        }

        // does not have objects so grant access since later objects will be filtered out by SecurityFilter
        if (objectUUIDs.isEmpty()) {
            return ACCESS_GRANTED;
        }

        // evaluate if objects owners equal to principal
        if (resource.hasOwner()) {
            long ownerCount = ownerAssociationRepository.countByOwnerUuidAndResourceAndObjectUuidIn(UUID.fromString(principal.getUserUuid()), resource, objectUUIDs.stream().filter(u -> u.getValue() != null).map(SecuredUUID::getValue).toList());
            if (ownerCount == objectUUIDs.size()) {
                return ACCESS_GRANTED;
            }
        }

        // evaluate group members permissions on objects assigned groups
        if (resource.hasGroups() && (resourceAction == ResourceAction.LIST || resourceAction == ResourceAction.DETAIL)) {
            properties.clear();
            properties.put(NAME_PROP_NAME, Resource.GROUP.getCode());
            properties.put(ACTION_PROP_NAME, ResourceAction.MEMBERS.getCode());

            for (SecuredUUID objectUuid : objectUUIDs) {
                // load groups associations
                List<String> groupUuids = groupAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid.getValue()).stream().map(g -> g.getGroupUuid().toString()).toList();
                if (groupUuids.isEmpty()) {
                    return ACCESS_DENIED;
                }
                OpaRequestedResource opaRequest = new OpaRequestedResource(properties);
                opaRequest.setObjectUUIDs(groupUuids);

                OpaResourceAccessResult result = this.checkAccess(principal.getRawData(), opaRequest);
                if (!result.isAuthorized()) {
                    logger.trace(String.format("Access to the method '%s' object has been denied by missing group member permissions.", methodInvocation.getMethod().getName()));
                    return ACCESS_DENIED;
                }
            }

            logger.trace(String.format("Access to the method '%s' object has been granted by group member permissions.", methodInvocation.getMethod().getName()));
            return ACCESS_GRANTED;
        }

        return ACCESS_DENIED;
    }

    private int vote(String principal, MethodInvocation methodInvocation, List<ExternalAuthorizationConfigAttribute> attributes) {
        try {
            Map<String, String> properties = attributes
                    .stream()
                    .filter(this::shouldBeSendToOpa)
                    .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::getAttributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));

            Optional<ParentUUIDGetter> parentUUIDGetter = getParentUUIDGetter(attributes);
            if (!Resource.NONE.getCode().equals(properties.get(PARENT_NAME_PROP_NAME))) {
                int result = voteResource(principal, methodInvocation, properties, parentUUIDGetter, true);
                if (result == ACCESS_DENIED) {
                    setDeniedResource(properties.get(PARENT_NAME_PROP_NAME));
                    setDeniedResourceAction(properties.get(PARENT_ACTION_PROP_NAME));
                    return result;
                }
            }

            return voteResource(principal, methodInvocation, properties, parentUUIDGetter, false);
        } catch (Exception e) {
            logger.error(String.format("Unable verify access to the method '%s'. Voting to deny access.", methodInvocation.getMethod().getName()), e);
            return ACCESS_DENIED;
        }
    }

    private int voteResource(String principal, MethodInvocation methodInvocation, Map<String, String> properties, Optional<ParentUUIDGetter> parentUUIDGetter, boolean parentResource) {
        Map<String, String> voteProperties = properties;

        if (parentResource) {
            Map<String, String> parentProperties = properties.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            parentProperties.put(NAME_PROP_NAME, properties.get(PARENT_NAME_PROP_NAME));
            parentProperties.put(ACTION_PROP_NAME, properties.get(PARENT_ACTION_PROP_NAME));
            voteProperties = parentProperties;
        }
        voteProperties.remove(PARENT_NAME_PROP_NAME);
        voteProperties.remove(PARENT_ACTION_PROP_NAME);

        OpaRequestedResource resource = new OpaRequestedResource(voteProperties);

        // UUIDs of objects the operation is executed on
        List<SecuredUUID> objectUUIDs = parentResource ? extractParentUUIDsFromMethodArguments(methodInvocation) : extractUUIDsFromMethodArguments(methodInvocation);

        // Parent UUID Getter not used for now, remove later
        if (!parentResource && parentUUIDGetter.isPresent()) {
            if (objectUUIDs.isEmpty()) {
                logger.error("ParentUUIDGetter specified but no object uuids were found. Access will be denied.");
                setDeniedResource(voteProperties.get(NAME_PROP_NAME));
                setDeniedResourceAction(voteProperties.get(ACTION_PROP_NAME));
                return ACCESS_DENIED;
            } else {
                List<String> parentsUUIDs = parentUUIDGetter.get().getParentsUUID(
                        objectUUIDs.stream()
                                .map(u -> u.getValue() == null ? "NULL" : u.toString()).toList());
                resource.setParentObjectUUIDs(parentsUUIDs);
            }

        }

        if (!objectUUIDs.isEmpty()) {
            List<String> uuids = objectUUIDs.stream()
                    .map(u -> u.getValue() == null ? "NULL" : u.toString()).toList();
            resource.setObjectUUIDs(uuids);
        }

        OpaResourceAccessResult result = this.checkAccess(principal, resource);
        if (result.isAuthorized()) {
            logger.trace(
                    String.format(
                            "Access to the method '%s' has been granted by the following rules [%s].",
                            methodInvocation.getMethod().getName(),
                            String.join(",", result.getAllow())
                    )
            );
            return ACCESS_GRANTED;
        } else {
            logger.trace(String.format("Access to the method '%s' has been denied.", methodInvocation.getMethod().getName()));
            setDeniedResource(voteProperties.get(NAME_PROP_NAME));
            setDeniedResourceAction(voteProperties.get(ACTION_PROP_NAME));
            return ACCESS_DENIED;
        }
    }

    @Override
    protected boolean canDecide(Authentication auth, MethodInvocation object) {
        return true;
    }

    protected OpaResourceAccessResult checkAccess(String principal, OpaRequestedResource resource) {
        try {
            return this.opaClient.checkResourceAccess(OpaPolicy.METHOD.policyName, resource, principal, new OpaRequestDetails(null));
        } catch (Exception e) {
            logger.error(
                    
                            "An error occurred during the authorization request to the OPA policy '%s'.".formatted(
                            OpaPolicy.METHOD.policyName),
                    e
            );
            return OpaResourceAccessResult.unauthorized();
        }
    }

    private Optional<ParentUUIDGetter> getParentUUIDGetter(List<ExternalAuthorizationConfigAttribute> attributes) throws InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        @SuppressWarnings("unchecked")
        Optional<Class<ParentUUIDGetter>> parentUUIDGetterClass = attributes.stream()
                .filter(att -> {
                    Object value = att.getAttributeValue();
                    return (value instanceof Class<?> c) &&
                            ParentUUIDGetter.class.isAssignableFrom(c) &&
                            !NoOpParentUUIDGetter.class.isAssignableFrom(c);
                })
                .map(att -> (Class<ParentUUIDGetter>) att.getAttributeValue())
                .findFirst();

        Optional<ParentUUIDGetter> parentUUIDGetter = Optional.empty();
        if (parentUUIDGetterClass.isPresent()) {
            parentUUIDGetter = Optional.of(parentUUIDGetterClass.get().getConstructor().newInstance());
        }
        return parentUUIDGetter;
    }

    @SuppressWarnings("unchecked")
    private List<SecuredUUID> extractUUIDsFromMethodArguments(MethodInvocation methodInvocation) {
        List<SecuredUUID> uuids = new ArrayList<>();

        Arrays.stream(methodInvocation.getArguments())
                .filter(arg -> arg instanceof SecuredUUID && !(arg instanceof SecuredParentUUID))
                .forEach(arg -> uuids.add((SecuredUUID) arg));

        Arrays.stream(methodInvocation.getArguments())
                .filter(arg -> arg instanceof List<?> l && !l.isEmpty() && l.get(0) instanceof SecuredUUID && !(l.get(0) instanceof SecuredParentUUID))
                .forEach(arg -> uuids.addAll(((List<SecuredUUID>) arg)));

        return uuids;
    }

    @SuppressWarnings("unchecked")
    private List<SecuredUUID> extractParentUUIDsFromMethodArguments(MethodInvocation methodInvocation) {
        List<SecuredUUID> uuids = new ArrayList<>();

        Arrays.stream(methodInvocation.getArguments())
                .filter(SecuredParentUUID.class::isInstance)
                .forEach(arg -> uuids.add((SecuredParentUUID) arg));

        Arrays.stream(methodInvocation.getArguments())
                .filter(arg -> arg instanceof List<?> l && !l.isEmpty() && l.get(0) instanceof SecuredParentUUID)
                .forEach(arg -> uuids.addAll(((List<SecuredParentUUID>) arg)));

        return uuids;
    }

    @SuppressWarnings("unchecked")
    private boolean hasSecurityFilterParam(MethodInvocation methodInvocation) {
        return Arrays.stream(methodInvocation.getArguments()).anyMatch(arg -> arg instanceof SecurityFilter);
    }

    private boolean shouldBeSendToOpa(ExternalAuthorizationConfigAttribute att) {
        Object value = att.getAttributeValue();
        return value.getClass().isPrimitive() ||
                value instanceof String ||
                value instanceof Integer ||
                value instanceof Boolean ||
                value instanceof Float ||
                value instanceof Double;
    }

    private void setDeniedResource(String resourceName) {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute("INTERNAL_ATTRIB_DENIED_RESOURCE_NAME", resourceName, 121);
        }
    }

    private void setDeniedResourceAction(String resourceActionName) {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute("INTERNAL_ATTRIB_DENIED_RESOURCE_ACTION_NAME", resourceActionName, 121);
        }
    }
}
