package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.cmp.CmpProfileEditRequestDto;
import com.czertainly.api.model.client.cmp.CmpProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDto;
import com.czertainly.api.model.core.cmp.CmpProfileDetailDto;
import com.czertainly.api.model.core.cmp.CmpProfileDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.CmpProfileService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.CertificateUtil;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class CmpProfileServiceImpl implements CmpProfileService {

    private static final Logger logger = LoggerFactory.getLogger(CmpProfileServiceImpl.class);

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // Injectors
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    private CmpProfileRepository cmpProfileRepository;
    private RaProfileService raProfileService;
    private ExtendedAttributeService extendedAttributeService;
    private CertificateService certificateService;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setCmpProfileRepository(CmpProfileRepository cmpProfileRepository) {
        this.cmpProfileRepository = cmpProfileRepository;
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

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // Methods implementations
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.LIST)
    public List<CmpProfileDto> listCmpProfile(SecurityFilter filter) {
        logger.debug("Getting all the CMP Profiles available in the database");
        return cmpProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(CmpProfile::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DETAIL)
    public CmpProfileDetailDto getCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException {
        logger.info("Requesting the details for the CMP Profile with uuid {}", cmpProfileUuid);
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        CmpProfileDetailDto dto = cmpProfile.mapToDetailDto();
        getDtoAttributes(cmpProfile, dto);

        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.CREATE)
    public CmpProfileDetailDto createCmpProfile(CmpProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException {
        if (cmpProfileRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("CMP Profile " + request.getName() + " already exists");
        }

        CmpProfile cmpProfile = new CmpProfile();

        // set request protection method
        switch (request.getRequestProtectionMethod()) {
            case SHARED_SECRET -> {
                if (request.getSharedSecret() == null || request.getSharedSecret().isEmpty()) {
                    throw new ValidationException(ValidationError.create("Shared secret cannot be empty"));
                }
                cmpProfile.setSharedSecret(request.getSharedSecret());
            }
            case SIGNATURE -> {}
            default ->
                throw new ValidationException(ValidationError.create("Protection method for the CMP request not supported"));
        }

        // set response protection method
        switch (request.getResponseProtectionMethod()) {
            case SHARED_SECRET -> cmpProfile.setSigningCertificateUuid(null);
            case SIGNATURE -> {
                if (request.getSigningCertificateUuid() == null || request.getSigningCertificateUuid().isEmpty()) {
                    throw new ValidationException(ValidationError.create("Signing certificate cannot be empty"));
                }
                Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(request.getSigningCertificateUuid()));
                if (!CertificateUtil.isCertificateCmpAcceptable(certificate)) {
                    throw new ValidationException(ValidationError.create("Signing certificate cannot be used for CMP Profile"));
                }
                cmpProfile.setSigningCertificateUuid(UUID.fromString(request.getSigningCertificateUuid()));
            }
            default ->
                throw new ValidationException(ValidationError.create("Protection method for the CMP response not supported"));
        }

        // validate custom attributes
        attributeEngine.validateCustomAttributesContent(Resource.CMP_PROFILE, request.getCustomAttributes());

        // check if RA Profile is provided
        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null && !request.getRaProfileUuid().isEmpty()) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService.mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }

        // new CMP Profile is disabled by default
        cmpProfile.setEnabled(false);
        cmpProfile.setName(request.getName());
        cmpProfile.setDescription(request.getDescription());
        cmpProfile.setRaProfile(raProfile);
        cmpProfile.setRequestProtectionMethod(request.getRequestProtectionMethod());
        cmpProfile.setResponseProtectionMethod(request.getResponseProtectionMethod());

        cmpProfile = cmpProfileRepository.save(cmpProfile);

        CmpProfileDetailDto dto = cmpProfile.mapToDetailDto();

        updateDtoAttributes(
                cmpProfile,
                raProfile,
                request.getIssueCertificateAttributes(),
                request.getRevokeCertificateAttributes(),
                request.getCustomAttributes(),
                dto
        );

        logger.info("CMP Profile created successfully: name={}, uuid={}", cmpProfile.getName(), cmpProfile.getUuid());

        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.UPDATE)
    public CmpProfileDetailDto editCmpProfile(SecuredUUID cmpProfileUuid, CmpProfileEditRequestDto request) throws ConnectorException, AttributeException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);

        // set request protection method
        switch (request.getRequestProtectionMethod()) {
            case SHARED_SECRET -> {
                if (request.getSharedSecret() == null || request.getSharedSecret().isEmpty()) {
                    throw new ValidationException(ValidationError.create("Shared secret cannot be empty"));
                }
                cmpProfile.setSharedSecret(request.getSharedSecret());
            }
            case SIGNATURE -> cmpProfile.setSharedSecret(null);
            default ->
                    throw new ValidationException(ValidationError.create("Protection method for the CMP request not supported"));
        }

        // set response protection method
        switch (request.getResponseProtectionMethod()) {
            case SHARED_SECRET -> {}
            case SIGNATURE -> {
                if (request.getSigningCertificateUuid() == null || request.getSigningCertificateUuid().isEmpty()) {
                    throw new ValidationException(ValidationError.create("Signing certificate cannot be empty"));
                }
                Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(request.getSigningCertificateUuid()));
                if (!CertificateUtil.isCertificateCmpAcceptable(certificate)) {
                    throw new ValidationException(ValidationError.create("Signing certificate cannot be used for CMP Profile"));
                }
                cmpProfile.setSigningCertificateUuid(UUID.fromString(request.getSigningCertificateUuid()));
            }
            default ->
                    throw new ValidationException(ValidationError.create("Protection method for the CMP response not supported"));
        }

        // validate custom attributes
        attributeEngine.validateCustomAttributesContent(Resource.CMP_PROFILE, request.getCustomAttributes());

        // check if RA Profile is provided
        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null && !request.getRaProfileUuid().isEmpty()) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService.mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }

        // delete old connector data attributes content
        UUID oldConnectorUuid = cmpProfile.getRaProfile() == null ? null : cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();
        if (oldConnectorUuid != null) {
            ObjectAttributeContentInfo contentInfo = new ObjectAttributeContentInfo(oldConnectorUuid, Resource.CMP_PROFILE, cmpProfile.getUuid());
            attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, AttributeOperation.CERTIFICATE_ISSUE, contentInfo);
        }

        cmpProfile.setDescription(request.getDescription());
        cmpProfile.setRaProfile(raProfile);
        cmpProfile.setRequestProtectionMethod(request.getRequestProtectionMethod());
        cmpProfile.setResponseProtectionMethod(request.getResponseProtectionMethod());

        cmpProfileRepository.save(cmpProfile);

        CmpProfileDetailDto dto = cmpProfile.mapToDetailDto();

        updateDtoAttributes(
                cmpProfile,
                raProfile,
                request.getIssueCertificateAttributes(),
                request.getRevokeCertificateAttributes(),
                request.getCustomAttributes(),
                dto
        );

        logger.info("CMP Profile updated successfully: name={}, uuid={}", cmpProfile.getName(), cmpProfile.getUuid());

        return dto;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DELETE)
    public void deleteCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException, ValidationException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        deleteCmpProfile(cmpProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteCmpProfile(List<SecuredUUID> cmpProfileUuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            CmpProfile cmpProfile = null;
            try {
                cmpProfile = getCmpProfileEntity(cmpProfileUuid);
                deleteCmpProfile(cmpProfile);
            } catch (Exception e) {
                logger.error(e.getMessage());
                messages.add(new BulkActionMessageDto(cmpProfileUuid.toString(), cmpProfile != null ? cmpProfile.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkForceRemoveCmpProfiles(List<SecuredUUID> cmpProfileUuids) throws NotFoundException, ValidationException {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            CmpProfile cmpProfile = null;
            try {
                cmpProfile = getCmpProfileEntity(cmpProfileUuid);
                SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithCmpProfile(
                        cmpProfile.getUuid().toString(), SecurityFilter.create());
                // CMP Profile only from allowed ones, but that would make the forbidden RA Profiles point to non-existing CMP Profile.
                raProfileService.bulkRemoveAssociatedCmpProfile(
                        raProfiles.getAll().stream().map(UniquelyIdentifiedAndAudited::getSecuredParentUuid).collect(Collectors.toList()));
                deleteCmpProfile(cmpProfile);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages.add(new BulkActionMessageDto(cmpProfileUuid.toString(), cmpProfile != null ? cmpProfile.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void enableCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException {
        changeCmpStatus(cmpProfileUuid, true);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.ENABLE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void bulkEnableCmpProfile(List<SecuredUUID> cmpProfileUuids) {
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            try {
                changeCmpStatus(cmpProfileUuid, true);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void disableCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException {
        changeCmpStatus(cmpProfileUuid, false);
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.DISABLE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void bulkDisableCmpProfile(List<SecuredUUID> cmpProfileUuids) {
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            try {
                changeCmpStatus(cmpProfileUuid, false);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @AuditLogged(originator = ObjectType.FE, affected = ObjectType.CMP_PROFILE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.UPDATE)
    public void updateRaProfile(SecuredUUID cmpProfileUuid, String raProfileUuid) throws NotFoundException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        cmpProfile.setRaProfile(getRaProfile(raProfileUuid));
        cmpProfileRepository.save(cmpProfile);
    }

    @Override
    public List<CertificateDto> listCmpSigningCertificates() {
        return certificateService.listCmpSigningCertificates(SecurityFilter.create());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter) {
        return cmpProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(CmpProfile::mapToAccessControlObjects)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCmpProfileEntity(uuid);
        // Since there are is no parent to the CMP Profile, exclusive parent permission evaluation need not be done
    }

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // Helper private methods
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    private void getDtoAttributes(CmpProfile cmpProfile, CmpProfileDetailDto dto) {
        if (cmpProfile.getRaProfile() != null) {
            dto.setIssueCertificateAttributes(
                    attributeEngine.getObjectDataAttributesContent(
                            cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid(),
                            AttributeOperation.CERTIFICATE_ISSUE,
                            Resource.CMP_PROFILE,
                            cmpProfile.getUuid()
                    )
            );
            dto.setRevokeCertificateAttributes(
                    attributeEngine.getObjectDataAttributesContent(
                            cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid(),
                            AttributeOperation.CERTIFICATE_REVOKE,
                            Resource.CMP_PROFILE,
                            cmpProfile.getUuid()
                    )
            );
        }
        dto.setCustomAttributes(
                attributeEngine.getObjectCustomAttributesContent(
                        Resource.CMP_PROFILE,
                        cmpProfile.getUuid()
                )
        );
    }

    private void updateDtoAttributes(CmpProfile cmpProfile, RaProfile raProfile,
                                     List<RequestAttributeDto> issueCertificateAttributes,
                                     List<RequestAttributeDto> revokeCertificateAttributes,
                                     List<RequestAttributeDto> customAttributes,
                                     CmpProfileDetailDto dto) throws NotFoundException, AttributeException {
        dto.setCustomAttributes(
                attributeEngine.updateObjectCustomAttributesContent(
                        Resource.CMP_PROFILE,
                        cmpProfile.getUuid(),
                        customAttributes
                )
        );
        if (raProfile != null) {
            dto.setIssueCertificateAttributes(
                    attributeEngine.updateObjectDataAttributesContent(
                            raProfile.getAuthorityInstanceReference().getConnectorUuid(),
                            AttributeOperation.CERTIFICATE_ISSUE,
                            Resource.CMP_PROFILE,
                            cmpProfile.getUuid(),
                            issueCertificateAttributes
                    )
            );
            dto.setRevokeCertificateAttributes(
                    attributeEngine.updateObjectDataAttributesContent(
                            raProfile.getAuthorityInstanceReference().getConnectorUuid(),
                            AttributeOperation.CERTIFICATE_REVOKE,
                            Resource.CMP_PROFILE,
                            cmpProfile.getUuid(),
                            revokeCertificateAttributes
                    )
            );
        }
    }

    private CmpProfile getCmpProfileEntity(SecuredUUID cmpProfileUuid) throws NotFoundException {
        return cmpProfileRepository.findByUuid(cmpProfileUuid).orElseThrow(() -> new NotFoundException(CmpProfile.class, cmpProfileUuid));
    }

    private RaProfile getRaProfile(String raProfileUuid) throws NotFoundException {
        return raProfileService.getRaProfileEntity(SecuredUUID.fromString(raProfileUuid));
    }

    private void deleteCmpProfile(CmpProfile cmpProfile) {
        SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithCmpProfile(
                cmpProfile.getUuid().toString(), SecurityFilter.create());
        if (!raProfiles.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create(
                            String.format(
                                    "Cannot remove as there are associated RA Profiles (%d): %s",
                                    raProfiles.size(),
                                    raProfiles.getAllowed().stream().map(RaProfile::getName).collect(Collectors.joining(","))
                            )
                    )
            );
        } else {
            attributeEngine.deleteAllObjectAttributeContent(Resource.CMP_PROFILE, cmpProfile.getUuid());
            cmpProfileRepository.delete(cmpProfile);
        }
    }

    private void changeCmpStatus(SecuredUUID cmpProfileUuid, boolean enabled) throws NotFoundException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        cmpProfile.setEnabled(enabled);
        cmpProfileRepository.save(cmpProfile);
    }

}
