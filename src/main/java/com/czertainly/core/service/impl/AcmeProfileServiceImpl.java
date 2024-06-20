package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.acme.AcmeProfileEditRequestDto;
import com.czertainly.api.model.client.acme.AcmeProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.core.acme.AcmeProfileDto;
import com.czertainly.api.model.core.acme.AcmeProfileListDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.repository.AcmeProfileRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.AcmeProfileService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.ValidatorUtil;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class AcmeProfileServiceImpl implements AcmeProfileService {

    private static final Logger logger = LoggerFactory.getLogger(AcmeProfileServiceImpl.class);
    private final AcmeProfileRepository acmeProfileRepository;
    private RaProfileService raProfileService;
    private ExtendedAttributeService extendedAttributeService;
    private AttributeEngine attributeEngine;

    @Autowired
    public AcmeProfileServiceImpl(AcmeProfileRepository acmeProfileRepository) {
        this.acmeProfileRepository = acmeProfileRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileRepository) {
        this.raProfileService = raProfileRepository;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.LIST)
    public List<AcmeProfileListDto> listAcmeProfile(SecurityFilter filter) {
        logger.debug("Getting all the ACME Profiles available in the database");
        List<AcmeProfileListDto> acmeProfileListDtos = acmeProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(AcmeProfile::mapToDtoSimple)
                .collect(Collectors.toList());
        return acmeProfileListDtos;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DETAIL)
    public AcmeProfileDto getAcmeProfile(SecuredUUID uuid) throws NotFoundException {
        logger.info("Requesting the details for the ACME Profile with uuid " + uuid);
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        AcmeProfileDto dto = acmeProfile.mapToDto();
        if (acmeProfile.getRaProfile() != null) {
            dto.setIssueCertificateAttributes(attributeEngine.getObjectDataAttributesContent(acmeProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_ISSUE, Resource.ACME_PROFILE, acmeProfile.getUuid()));
            dto.setRevokeCertificateAttributes(attributeEngine.getObjectDataAttributesContent(acmeProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_REVOKE, Resource.ACME_PROFILE, acmeProfile.getUuid()));
        }
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.ACME_PROFILE, uuid.getValue()));
        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.CREATE)
    public AcmeProfileDto createAcmeProfile(AcmeProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException {
        if (request.getName() == null || request.getName().isEmpty()) {
            throw new ValidationException(ValidationError.create("Name cannot be empty"));
        }
        if (ValidatorUtil.containsUnreservedCharacters(request.getName())) {
            throw new ValidationException(ValidationError.create("Name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
        }
        if (request.getValidity() != null && request.getValidity() < 0) {
            throw new ValidationException(ValidationError.create("Order Validity cannot be less than 0"));
        }
        if (request.getRetryInterval() != null && request.getRetryInterval() < 0) {
            throw new ValidationException(ValidationError.create("Retry Interval cannot be less than 0"));
        }

        logger.info("Creating a new ACME Profile");

        if (acmeProfileRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("ACME Profile with same name already exists");
        }

        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null && !request.getRaProfileUuid().isEmpty()) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            if (ValidatorUtil.containsUnreservedCharacters(raProfile.getName())) {
                throw new ValidationException(ValidationError.create("RA Profile name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
            }
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService.mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }

        attributeEngine.validateCustomAttributesContent(Resource.ACME_PROFILE, request.getCustomAttributes());

        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setEnabled(false);
        acmeProfile.setName(request.getName());
        acmeProfile.setDescription(request.getDescription());
        acmeProfile.setDnsResolverIp(request.getDnsResolverIp());
        acmeProfile.setDnsResolverPort(request.getDnsResolverPort());
        acmeProfile.setRetryInterval(Optional.ofNullable(request.getRetryInterval()).orElse(36000));
        acmeProfile.setValidity(Optional.ofNullable(request.getValidity()).orElse(30));
        acmeProfile.setWebsite(request.getWebsiteUrl());
        acmeProfile.setTermsOfServiceUrl(request.getTermsOfServiceUrl());
        acmeProfile.setRequireContact(request.isRequireContact());
        acmeProfile.setRequireTermsOfService(request.isRequireTermsOfService());
        acmeProfile.setDisableNewOrders(false);
        acmeProfile.setRaProfile(raProfile);
        acmeProfile = acmeProfileRepository.save(acmeProfile);

        AcmeProfileDto dto = acmeProfile.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ACME_PROFILE, acmeProfile.getUuid(), request.getCustomAttributes()));
        if (raProfile != null) {
            dto.setIssueCertificateAttributes(attributeEngine.updateObjectDataAttributesContent(raProfile.getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_ISSUE, Resource.ACME_PROFILE, acmeProfile.getUuid(), request.getIssueCertificateAttributes()));
            dto.setRevokeCertificateAttributes(attributeEngine.updateObjectDataAttributesContent(raProfile.getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_REVOKE, Resource.ACME_PROFILE, acmeProfile.getUuid(), request.getRevokeCertificateAttributes()));
        }

        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.UPDATE)
    public AcmeProfileDto editAcmeProfile(SecuredUUID uuid, AcmeProfileEditRequestDto request) throws ConnectorException, AttributeException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        attributeEngine.validateCustomAttributesContent(Resource.ACME_PROFILE, request.getCustomAttributes());

        if (request.isRequireContact() != null) {
            acmeProfile.setRequireContact(request.isRequireContact());
        }
        if (request.isRequireTermsOfService() != null) {
            acmeProfile.setRequireTermsOfService(request.isRequireTermsOfService());
        }
        if (request.isTermsOfServiceChangeDisable() != null) {
            acmeProfile.setDisableNewOrders(request.isTermsOfServiceChangeDisable());
        }

        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            if (ValidatorUtil.containsUnreservedCharacters(raProfile.getName())) {
                throw new ValidationException(ValidationError.create("RA Profile name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
            }
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService.mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }

        // delete old connector data attributes content
        UUID oldConnectorUuid = acmeProfile.getRaProfile() == null ? null : acmeProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();
        if (oldConnectorUuid != null) {
            ObjectAttributeContentInfo contentInfo = new ObjectAttributeContentInfo(oldConnectorUuid, Resource.ACME_PROFILE, acmeProfile.getUuid());
            attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, AttributeOperation.CERTIFICATE_ISSUE, contentInfo);
            attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, AttributeOperation.CERTIFICATE_REVOKE, contentInfo);
        }

        acmeProfile.setRaProfile(raProfile);

        acmeProfile.setDescription(request.getDescription());

        acmeProfile.setDnsResolverIp(request.getDnsResolverIp());
        acmeProfile.setDnsResolverPort(request.getDnsResolverPort());

        if (request.getRetryInterval() != null) {
            if (request.getRetryInterval() < 0) {
                throw new ValidationException(ValidationError.create("Retry Interval cannot be less than 0"));
            }
            acmeProfile.setRetryInterval(request.getRetryInterval());
        } else {
            acmeProfile.setRetryInterval(null);
        }
        if (request.getValidity() != null) {
            if (request.getValidity() < 0) {
                throw new ValidationException(ValidationError.create("Order Validity cannot be less than 0"));
            }
            acmeProfile.setValidity(request.getValidity());
        } else {
            acmeProfile.setValidity(null);
        }
        acmeProfile.setTermsOfServiceUrl(request.getTermsOfServiceUrl());
        acmeProfile.setWebsite(request.getWebsiteUrl());
        acmeProfile.setDisableNewOrders(request.isTermsOfServiceChangeDisable());
        acmeProfile.setTermsOfServiceChangeUrl(request.getTermsOfServiceChangeUrl());
        acmeProfile = acmeProfileRepository.save(acmeProfile);

        AcmeProfileDto dto = acmeProfile.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ACME_PROFILE, acmeProfile.getUuid(), request.getCustomAttributes()));
        if (raProfile != null) {
            dto.setIssueCertificateAttributes(attributeEngine.updateObjectDataAttributesContent(raProfile.getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_ISSUE, Resource.ACME_PROFILE, acmeProfile.getUuid(), request.getIssueCertificateAttributes()));
            dto.setRevokeCertificateAttributes(attributeEngine.updateObjectDataAttributesContent(raProfile.getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_REVOKE, Resource.ACME_PROFILE, acmeProfile.getUuid(), request.getRevokeCertificateAttributes()));
        }

        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DELETE)
    public void deleteAcmeProfile(SecuredUUID uuid) throws NotFoundException, ValidationException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        deleteAcmeProfile(acmeProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void enableAcmeProfile(SecuredUUID uuid) throws NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        if (acmeProfile.isEnabled() != null && acmeProfile.isEnabled()) {
            throw new RuntimeException("ACME Profile is already enabled");
        }
        acmeProfile.setEnabled(true);
        acmeProfileRepository.save(acmeProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void disableAcmeProfile(SecuredUUID uuid) throws NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        if (!acmeProfile.isEnabled()) {
            throw new RuntimeException("ACME Profile is already disabled");
        }
        acmeProfile.setEnabled(false);
        acmeProfileRepository.save(acmeProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void bulkEnableAcmeProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
                if (acmeProfile.isEnabled()) {
                    logger.warn("ACME Profile is already enabled");
                }
                acmeProfile.setEnabled(true);
                acmeProfileRepository.save(acmeProfile);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void bulkDisableAcmeProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
                if (acmeProfile.isEnabled() != null && acmeProfile.isEnabled()) {
                    logger.warn("ACME Profile is already disabled");
                }
                acmeProfile.setEnabled(false);
                acmeProfileRepository.save(acmeProfile);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteAcmeProfile(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            AcmeProfile acmeProfile = null;
            try {
                acmeProfile = getAcmeProfileEntity(uuid);
                deleteAcmeProfile(acmeProfile);
            } catch (Exception e) {
                logger.error(e.getMessage());
                messages.add(new BulkActionMessageDto(uuid.toString(), acmeProfile != null ? acmeProfile.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.UPDATE)
    public void updateRaProfile(SecuredUUID uuid, String raProfileUuid) throws NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        acmeProfile.setRaProfile(getRaProfile(raProfileUuid));
        acmeProfileRepository.save(acmeProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.ACME_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkForceRemoveACMEProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            AcmeProfile acmeProfile = null;
            try {
                acmeProfile = getAcmeProfileEntity(uuid);
                SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithAcmeProfile(acmeProfile.getUuid().toString(), SecurityFilter.create());
                // acme profile only from allowed ones, but that would make the forbidden ra profiles point to nonexistent acme profile.
                raProfileService.bulkRemoveAssociatedAcmeProfile(raProfiles.getAll().stream().map(UniquelyIdentifiedAndAudited::getSecuredUuid).collect(Collectors.toList()));
                deleteAcmeProfile(acmeProfile);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages.add(new BulkActionMessageDto(uuid.toString(), acmeProfile != null ? acmeProfile.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return acmeProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(AcmeProfile::mapToAccessControlObjects)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getAcmeProfileEntity(uuid);
        // Since there are is no parent to the ACME Profile, exclusive parent permission evaluation need not be done
    }


    private RaProfile getRaProfile(String uuid) throws NotFoundException {
        return raProfileService.getRaProfileEntity(SecuredUUID.fromString(uuid));
    }

    private AcmeProfile getAcmeProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return acmeProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(AcmeProfile.class, uuid));
    }

    private void deleteAcmeProfile(AcmeProfile acmeProfile) {
        SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithAcmeProfile(acmeProfile.getUuid().toString(), SecurityFilter.create());
        if (!raProfiles.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create(
                            String.format(
                                    "Dependent RA Profiles (%d): %s",
                                    raProfiles.size(),
                                    raProfiles.getAllowed().stream().map(RaProfile::getName).collect(Collectors.joining(","))
                            )
                    )
            );
        } else {
            attributeEngine.deleteAllObjectAttributeContent(Resource.ACME_PROFILE, acmeProfile.getUuid());
            acmeProfileRepository.delete(acmeProfile);
        }
    }
}

