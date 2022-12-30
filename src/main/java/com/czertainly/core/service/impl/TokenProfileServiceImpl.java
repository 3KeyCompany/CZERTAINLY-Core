package com.czertainly.core.service.impl;

import com.czertainly.api.clients.cryptography.TokenInstanceApiClient;
import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.czertainly.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.czertainly.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.dao.repository.TokenProfileRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.AttributeService;
import com.czertainly.core.service.TokenProfileService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class TokenProfileServiceImpl implements TokenProfileService {

    private static final Logger logger = LoggerFactory.getLogger(TokenProfileServiceImpl.class);


    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private AttributeService attributeService;
    private TokenInstanceApiClient tokenInstanceApiClient;
    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private TokenProfileRepository tokenProfileRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;


    @Autowired
    public void setTokenProfileRepository(TokenProfileRepository tokenProfileRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    @Autowired
    public void setTokenInstanceApiClient(TokenInstanceApiClient tokenInstanceApiClient) {
        this.tokenInstanceApiClient = tokenInstanceApiClient;
    }

    //-------------------------------------------------------------------------------------
    //Service Implementations
    //-------------------------------------------------------------------------------------
    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public List<TokenProfileDto> listTokenProfiles(Optional<Boolean> enabled, SecurityFilter filter) {
        filter.setParentRefProperty("tokenInstanceReferenceUuid");
        if (enabled == null || !enabled.isPresent()) {
            return tokenProfileRepository.findUsingSecurityFilter(filter)
                    .stream()
                    .map(TokenProfile::mapToDto)
                    .collect(Collectors.toList());
        } else {
            return tokenProfileRepository.findUsingSecurityFilter(filter, enabled.get())
                    .stream()
                    .map(TokenProfile::mapToDto)
                    .collect(Collectors.toList());
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto getTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));

        TokenProfileDetailDto dto = tokenProfile.mapToDetailDto();
        dto.setCustomAttributes(attributeService.getCustomAttributesWithValues(tokenProfile.getUuid(), Resource.TOKEN_PROFILE));
        return dto;
    }

    @Override
    public TokenProfileDetailDto createTokenProfile(SecuredParentUUID tokenInstanceUuid, AddTokenProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException {
        if (StringUtils.isBlank(request.getName())) {
            throw new ValidationException("Token Profile name must not be empty");
        }

        Optional<TokenProfile> o = tokenProfileRepository.findByName(request.getName());
        if (o.isPresent()) {
            throw new AlreadyExistException(TokenProfile.class, request.getName());
        }
        attributeService.validateCustomAttributes(request.getCustomAttributes(), Resource.TOKEN_PROFILE);
        TokenInstanceReference tokenInstanceReference = tokenInstanceReferenceRepository.findByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstanceReferenceRepository.class, tokenInstanceUuid));

        List<DataAttribute> attributes = mergeAndValidateAttributes(tokenInstanceReference, request.getAttributes());
        TokenProfile tokenProfile = createTokenProfile(request, attributes, tokenInstanceReference);
        tokenProfileRepository.save(tokenProfile);

        attributeService.createAttributeContent(tokenProfile.getUuid(), request.getCustomAttributes(), Resource.TOKEN_PROFILE);

        TokenProfileDetailDto tokenProfileDetailDto = tokenProfile.mapToDetailDto();
        tokenProfileDetailDto.setCustomAttributes(attributeService.getCustomAttributesWithValues(tokenProfile.getUuid(), Resource.TOKEN_PROFILE));

        return tokenProfileDetailDto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto editTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid, EditTokenProfileRequestDto request) throws ConnectorException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));

        TokenInstanceReference tokenInstanceReference = tokenInstanceReferenceRepository.findByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, tokenInstanceUuid));

        attributeService.validateCustomAttributes(request.getCustomAttributes(), Resource.TOKEN_PROFILE);
        List<DataAttribute> attributes = mergeAndValidateAttributes(tokenInstanceReference, request.getAttributes());

        tokenProfile = updateTokenProfile(tokenProfile, tokenInstanceReference, request, attributes);
        tokenProfileRepository.save(tokenProfile);

        attributeService.updateAttributeContent(tokenProfile.getUuid(), request.getCustomAttributes(), Resource.TOKEN_PROFILE);

        TokenProfileDetailDto tokenProfileDetailDto = tokenProfile.mapToDetailDto();
        tokenProfileDetailDto.setCustomAttributes(attributeService.getCustomAttributesWithValues(tokenProfile.getUuid(), Resource.TOKEN_PROFILE));
        return tokenProfileDetailDto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public void deleteTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        deleteProfileInternal(uuid, false);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE)
    public void deleteTokenProfile(SecuredUUID tokenProfileUuid) throws NotFoundException {
        deleteProfileInternal(tokenProfileUuid, true);

    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public void disableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        disableProfileInternal(uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public void enableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        enableProfileInternal(uuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public void deleteTokenProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                deleteProfileInternal(uuid, false);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public void disableTokenProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                disableProfileInternal(uuid);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.TOKEN_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN_INSTANCE, parentAction = ResourceAction.DETAIL)
    public void enableTokenProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                enableProfileInternal(uuid);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return tokenProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(TokenProfile::mapToAccessControlObjects)
                .collect(Collectors.toList());
    }

    private List<DataAttribute> mergeAndValidateAttributes(TokenInstanceReference tokenInstanceRef, List<RequestAttributeDto> attributes) throws ConnectorException {
        List<BaseAttribute> definitions = tokenInstanceApiClient.listTokenProfileAttributes(
                tokenInstanceRef.getConnector().mapToDto(),
                tokenInstanceRef.getTokenInstanceUuid());

        List<String> existingAttributesFromConnector = definitions.stream().map(BaseAttribute::getName).collect(Collectors.toList());
        for (RequestAttributeDto requestAttributeDto : attributes) {
            if (!existingAttributesFromConnector.contains(requestAttributeDto.getName())) {
                DataAttribute referencedAttribute = attributeService.getReferenceAttribute(tokenInstanceRef.getConnectorUuid(), requestAttributeDto.getName());
                if (referencedAttribute != null) {
                    definitions.add(referencedAttribute);
                }
            }
        }

        List<DataAttribute> merged = AttributeDefinitionUtils.mergeAttributes(definitions, attributes);

        tokenInstanceApiClient.validateTokenProfileAttributes(
                tokenInstanceRef.getConnector().mapToDto(),
                tokenInstanceRef.getTokenInstanceUuid(),
                attributes);

        return merged;
    }

    private TokenProfile createTokenProfile(AddTokenProfileRequestDto request, List<DataAttribute> attributes, TokenInstanceReference tokenInstanceReference) {
        TokenProfile entity = new TokenProfile();
        entity.setName(request.getName());
        entity.setDescription(request.getDescription());
        entity.setAttributes(AttributeDefinitionUtils.serialize(attributes));
        entity.setEnabled(request.isEnabled());
        entity.setTokenInstanceName(tokenInstanceReference.getName());
        entity.setTokenInstanceReference(tokenInstanceReference);
        entity.setTokenInstanceReferenceUuid(tokenInstanceReference.getUuid());
        return entity;
    }

    private TokenProfile updateTokenProfile(TokenProfile entity, TokenInstanceReference tokenInstanceReference, EditTokenProfileRequestDto request, List<DataAttribute> attributes) {
        if (request.getDescription() != null) entity.setDescription(request.getDescription());
        entity.setAttributes(AttributeDefinitionUtils.serialize(attributes));
        entity.setTokenInstanceReference(tokenInstanceReference);
        if (request.getEnabled() != null) entity.setEnabled(request.getEnabled() != null && request.getEnabled());
        entity.setTokenInstanceName(tokenInstanceReference.getName());
        return entity;
    }

    //TODO - Check and delete the other associated objects
    private void deleteProfileInternal(SecuredUUID uuid, boolean throwWhenAssociated) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));
        if (throwWhenAssociated && tokenProfile.getTokenInstanceReference() == null) {
            throw new ValidationException(ValidationError.create("Token Profile has associated Token Instance. Use other API"));
        }
        attributeService.deleteAttributeContent(tokenProfile.getUuid(), Resource.TOKEN_PROFILE);
        tokenProfileRepository.delete(tokenProfile);
    }

    private void disableProfileInternal(SecuredUUID uuid) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));
        tokenProfile.setEnabled(false);
        tokenProfileRepository.save(tokenProfile);
    }

    private void enableProfileInternal(SecuredUUID uuid) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));
        tokenProfile.setEnabled(true);
        tokenProfileRepository.save(tokenProfile);
    }
}
