package com.czertainly.core.service.v2.impl;

import com.czertainly.api.clients.v2.CertificateApiClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.location.PushToLocationRequestDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.connector.v2.CertRevocationDto;
import com.czertainly.api.model.connector.v2.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v2.CertificateRenewRequestDto;
import com.czertainly.api.model.connector.v2.CertificateSignRequestDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.certificate.CertificateStatus;
import com.czertainly.api.model.core.v2.*;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.attribute.CsrAttributes;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.producers.ActionProducer;
import com.czertainly.core.messaging.producers.NotificationProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.*;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.*;
import jakarta.transaction.Transactional;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Service("clientOperationServiceImplV2")
@Transactional
public class ClientOperationServiceImpl implements ClientOperationService {
    private static final Logger logger = LoggerFactory.getLogger(ClientOperationServiceImpl.class);
    private RaProfileRepository raProfileRepository;
    private CertificateRepository certificateRepository;
    private LocationService locationService;
    private CertificateService certificateService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private ExtendedAttributeService extendedAttributeService;
    private CertValidationService certValidationService;
    private CertificateApiClient certificateApiClient;
    private MetadataService metadataService;
    private AttributeService attributeService;
    private CryptographicOperationService cryptographicOperationService;
    private CryptographicKeyService keyService;

    private ActionProducer actionProducer;

    private NotificationProducer notificationProducer;

    @Autowired
    public void setActionProducer(ActionProducer actionProducer) {
        this.actionProducer = actionProducer;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Lazy
    @Autowired
    public void setLocationService(LocationService locationService) {
        this.locationService = locationService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Autowired
    public void setCertValidationService(CertValidationService certValidationService) {
        this.certValidationService = certValidationService;
    }

    @Autowired
    public void setCertificateApiClient(CertificateApiClient certificateApiClient) {
        this.certificateApiClient = certificateApiClient;
    }

    @Autowired
    public void setMetadataService(MetadataService metadataService) {
        this.metadataService = metadataService;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setCryptographicOperationService(CryptographicOperationService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Autowired
    public void setKeyService(CryptographicKeyService keyService) {
        this.keyService = keyService;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid) throws ConnectorException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.listIssueCertificateAttributes(raProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.VALIDATE)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public boolean validateIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.validateIssueCertificateAttributes(raProfile, attributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateDetailDto submitCertificateRequest(ClientCertificateRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        // validate custom Attributes
        if (!AuthHelper.isLoggedProtocolUser()) {
            attributeService.validateCustomAttributes(request.getCustomAttributes(), Resource.CERTIFICATE);
        }
        if (request.getPkcs10() == null && (request.getKeyUuid() == null || request.getTokenProfileUuid() == null)) {
            throw new ValidationException("Cannot submit certificate request without specifying key or uploaded request content");
        }

        Map<String, Object> csrMap = generateCsr(request.getPkcs10(), request.getCsrAttributes(), request.getKeyUuid(), request.getTokenProfileUuid(), request.getSignatureAttributes());
        String pkcs10 = (String) csrMap.get("csr");
        List<DataAttribute> merged = (List<DataAttribute>) csrMap.get("merged");
        CertificateDetailDto certificate = certificateService.submitCertificateRequest(pkcs10, request.getSignatureAttributes(), merged, request.getIssueAttributes(), request.getKeyUuid(), request.getRaProfileUuid(), request.getSourceCertificateUuid());

        // create custom Attributes
        attributeService.createAttributeContent(UUID.fromString(certificate.getUuid()), request.getCustomAttributes(), Resource.CERTIFICATE);

        return certificate;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.ISSUE)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto issueCertificate(final SecuredParentUUID authorityUuid, final SecuredUUID raProfileUuid, final ClientCertificateSignRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        ClientCertificateRequestDto certificateRequestDto = new ClientCertificateRequestDto();
        certificateRequestDto.setRaProfileUuid(raProfileUuid.getValue());
        certificateRequestDto.setCsrAttributes(request.getCsrAttributes());
        certificateRequestDto.setSignatureAttributes(request.getSignatureAttributes());
        certificateRequestDto.setPkcs10(request.getPkcs10());
        certificateRequestDto.setTokenProfileUuid(request.getTokenProfileUuid());
        certificateRequestDto.setKeyUuid(request.getKeyUuid());
        certificateRequestDto.setIssueAttributes(request.getAttributes());
        certificateRequestDto.setCustomAttributes(request.getCustomAttributes());

        CertificateDetailDto certificate = submitCertificateRequest(certificateRequestDto);

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setAuthorityUuid(authorityUuid.getValue());
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.ISSUE);
        actionMessage.setResourceUuid(UUID.fromString(certificate.getUuid()));
        actionMessage.setRaProfileUuid(raProfileUuid.getValue());
        actionProducer.produceMessage(actionMessage);

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(certificate.getUuid());
        return response;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.ISSUE)
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ISSUE)
    public void issueCertificateAction(final UUID certificateUuid, boolean isApproved) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException {
        if (!isApproved) {
            certificateService.checkIssuePermissions();
        }
        issueCertificateInternal(certificateUuid);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.ISSUE)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto issueNewCertificate(final SecuredParentUUID authorityUuid, final SecuredUUID raProfileUuid, final String certificateUuid) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException {
        certificateService.checkIssuePermissions();
        return issueCertificateInternal(UUID.fromString(certificateUuid));
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.RENEW)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRenewRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        Certificate oldCertificate = validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.RENEW);

        // CSR decision making
        String requestContent;
        if (request.getPkcs10() != null) {
            requestContent = request.getPkcs10();
            validatePublicKeyForCsrAndCertificate(oldCertificate.getCertificateContent().getContent(), requestContent, true);
        } else {
            // Check if the request is for using the existing CSR
            requestContent = getExistingCsr(oldCertificate);
        }

        ClientCertificateRequestDto certificateRequestDto = new ClientCertificateRequestDto();
        certificateRequestDto.setRaProfileUuid(raProfileUuid.getValue());
        certificateRequestDto.setPkcs10(requestContent);
        certificateRequestDto.setKeyUuid(oldCertificate.getKeyUuid());
        certificateRequestDto.setSourceCertificateUuid(oldCertificate.getUuid());
        certificateRequestDto.setCustomAttributes(AttributeDefinitionUtils.getClientAttributes(attributeService.getCustomAttributesWithValues(oldCertificate.getUuid(), Resource.CERTIFICATE)));

        CertificateDetailDto newCertificate = submitCertificateRequest(certificateRequestDto);

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setAuthorityUuid(authorityUuid.getValue());
        actionMessage.setData(request);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.RENEW);
        actionMessage.setResourceUuid(UUID.fromString(newCertificate.getUuid()));
        actionMessage.setRaProfileUuid(raProfileUuid.getValue());

        actionProducer.produceMessage(actionMessage);

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(newCertificate.getUuid());
        return response;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.RENEW)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void renewCertificateAction(final UUID certificateUuid, ClientCertificateRenewRequestDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRenewPermissions();
        }
        Certificate certificate = validateNewCertificateForOperation(certificateUuid);
        Certificate oldCertificate = certificateRepository.findByUuid(certificate.getSourceCertificateUuid()).orElseThrow(() -> new NotFoundException(Certificate.class, certificate.getSourceCertificateUuid()));
        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Renewing Certificate: ", oldCertificate);

        CertificateRenewRequestDto caRequest = new CertificateRenewRequestDto();
        caRequest.setPkcs10(certificate.getCertificateRequest().getContent());
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(raProfile.mapToDto().getAttributes()));
        caRequest.setCertificate(oldCertificate.getCertificateContent().getContent());
        caRequest.setMeta(metadataService.getMetadataWithSourceForCertificateRenewal(raProfile.getAuthorityInstanceReference().getConnectorUuid(), oldCertificate.getUuid(), Resource.CERTIFICATE, null, null));

        CertificateDataResponseDto renewCaResponse;
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        try {
            renewCaResponse = certificateApiClient.renewCertificate(
                    raProfile.getAuthorityInstanceReference().getConnector().mapToDto(),
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);

            logger.info("Certificate {} was renewed by authority", certificateUuid);

            CertificateDetailDto certificateDetailDto = certificateService.issueNewCertificate(certificateUuid, renewCaResponse.getCertificateData(), renewCaResponse.getMeta());

            additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
            certificateEventHistoryService.addEventHistory(CertificateEvent.RENEW, CertificateEventStatus.SUCCESS, "Renewed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation), oldCertificate);
        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.RENEW, CertificateEventStatus.FAILED, e.getMessage(), MetaDefinitions.serialize(additionalInformation), oldCertificate);
            certificateEventHistoryService.addEventHistory(CertificateEvent.ISSUE, CertificateEventStatus.FAILED, e.getMessage(), MetaDefinitions.serialize(additionalInformation), certificate);
            logger.error("Failed to renew Certificate", e.getMessage());
            throw new CertificateOperationException("Failed to renew certificate: " + e.getMessage());
        }

        Location location = null;
        try {
            /** replace certificate in the locations if needed */
            if (request.isReplaceInLocations()) {
                logger.info("Replacing certificates in locations for certificate: " + certificate.getUuid());
                for (CertificateLocation cl : oldCertificate.getLocations()) {
                    location = cl.getLocation();
                    PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
                    pushRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(cl.getPushAttributes()));

                    locationService.removeCertificateFromLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), oldCertificate.getUuid().toString());
                    certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Removed from Location " + cl.getLocation().getName(), "", oldCertificate);

                    locationService.pushCertificateToLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), certificate.getUuid().toString(), pushRequest);
                    certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Pushed to Location " + cl.getLocation().getName(), "", certificate);
                }
            }

        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.FAILED, String.format("Failed to replace certificate in location %s: %s", location != null ? location.getName() : "", e.getMessage()), "", certificate);
            logger.error("Failed to replace certificate in all locations during renew operation", e.getMessage());
            throw new CertificateOperationException("Failed to replace certificate in all locations during renew operation: " + e.getMessage());
        }

        // notify
        try {
            logger.debug("Sending notification of certificate renewal. Certificate: {}", certificate);
            List<NotificationRecipient> recipients = NotificationRecipient.buildUserOrGroupNotificationRecipient(certificate.getOwnerUuid(), certificate.getGroupUuid());
            notificationProducer.produceNotificationCertificateActionPerformed(Resource.CERTIFICATE, certificate.getUuid(), recipients, certificate.mapToListDto(), ResourceAction.RENEW.getCode(), null);
        } catch (Exception e) {
            logger.error("Sending notification for certificate renewal failed. Certificate: {}. Error: {}", certificate, e.getMessage());
        }

        logger.debug("Certificate Renewed: {}", certificate);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.RENEW)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto rekeyCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRekeyRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        Certificate oldCertificate = validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.REKEY);

        // CSR decision making
        ClientCertificateRequestDto certificateRequestDto = new ClientCertificateRequestDto();
        if (request.getPkcs10() != null) {
            String certificateContent = oldCertificate.getCertificateContent().getContent();
            validatePublicKeyForCsrAndCertificate(certificateContent, request.getPkcs10(), false);
            validateSubjectDnForCertificate(certificateContent, request.getPkcs10());

            certificateRequestDto.setPkcs10(request.getPkcs10());
        } else {
            UUID keyUuid = existingKeyValidation(request.getKeyUuid(), request.getSignatureAttributes(), oldCertificate);
            X509Certificate x509Certificate = CertificateUtil.parseCertificate(oldCertificate.getCertificateContent().getContent());
            X500Principal principal = x509Certificate.getSubjectX500Principal();
            // Gather the signature attributes either provided in the request or get it from the old certificate
            List<RequestAttributeDto> signatureAttributes = request.getSignatureAttributes() != null
                    ? request.getSignatureAttributes()
                    : (oldCertificate.getCertificateRequest() != null ? oldCertificate.getCertificateRequest().getSignatureAttributes() : null);

            String requestContent = generateCsr(
                    keyUuid,
                    getTokenProfileUuid(request.getTokenProfileUuid(), oldCertificate),
                    principal,
                    signatureAttributes
            );

            certificateRequestDto.setKeyUuid(keyUuid);
            certificateRequestDto.setPkcs10(requestContent);
            certificateRequestDto.setSignatureAttributes(signatureAttributes);
        }

        certificateRequestDto.setRaProfileUuid(raProfileUuid.getValue());
        certificateRequestDto.setSourceCertificateUuid(oldCertificate.getUuid());
        certificateRequestDto.setCustomAttributes(AttributeDefinitionUtils.getClientAttributes(attributeService.getCustomAttributesWithValues(oldCertificate.getUuid(), Resource.CERTIFICATE)));

        CertificateDetailDto newCertificate = submitCertificateRequest(certificateRequestDto);

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setAuthorityUuid(authorityUuid.getValue());
        actionMessage.setData(request);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.REKEY);
        actionMessage.setResourceUuid(UUID.fromString(newCertificate.getUuid()));
        actionMessage.setRaProfileUuid(raProfileUuid.getValue());

        actionProducer.produceMessage(actionMessage);

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(newCertificate.getUuid());
        return response;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.RENEW)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void rekeyCertificateAction(final UUID certificateUuid, ClientCertificateRekeyRequestDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRenewPermissions();
        }
        Certificate certificate = validateNewCertificateForOperation(certificateUuid);
        Certificate oldCertificate = certificateRepository.findByUuid(certificate.getSourceCertificateUuid()).orElseThrow(() -> new NotFoundException(Certificate.class, certificate.getSourceCertificateUuid()));
        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Rekeying Certificate: ", oldCertificate);
        CertificateRenewRequestDto caRequest = new CertificateRenewRequestDto();
        caRequest.setPkcs10(certificate.getCertificateRequest().getContent());
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(raProfile.mapToDto().getAttributes()));
        caRequest.setCertificate(oldCertificate.getCertificateContent().getContent());
        caRequest.setMeta(metadataService.getMetadataWithSourceForCertificateRenewal(raProfile.getAuthorityInstanceReference().getConnectorUuid(), oldCertificate.getUuid(), Resource.CERTIFICATE, null, null));

        CertificateDataResponseDto renewCaResponse = null;
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        try {
            renewCaResponse = certificateApiClient.renewCertificate(
                    raProfile.getAuthorityInstanceReference().getConnector().mapToDto(),
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);

            logger.info("Certificate {} was renewed by authority", certificateUuid);

            CertificateDetailDto certificateDetailDto = certificateService.issueNewCertificate(certificateUuid, renewCaResponse.getCertificateData(), renewCaResponse.getMeta());

            additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
            certificateEventHistoryService.addEventHistory(CertificateEvent.REKEY, CertificateEventStatus.SUCCESS, "Rekeyed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation), oldCertificate);
        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.REKEY, CertificateEventStatus.FAILED, e.getMessage(), MetaDefinitions.serialize(additionalInformation), oldCertificate);
            certificateEventHistoryService.addEventHistory(CertificateEvent.ISSUE, CertificateEventStatus.FAILED, e.getMessage(), MetaDefinitions.serialize(additionalInformation), certificate);
            logger.error("Failed to rekey Certificate", e.getMessage());
            throw new CertificateOperationException("Failed to rekey certificate: " + e.getMessage());
        }

        Location location = null;
        try {
            /** replace certificate in the locations if needed */
            if (request.isReplaceInLocations()) {
                logger.info("Replacing certificates in locations for certificate: " + certificate.getUuid());
                for (CertificateLocation cl : oldCertificate.getLocations()) {
                    location = cl.getLocation();
                    PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
                    pushRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(cl.getPushAttributes()));

                    locationService.removeCertificateFromLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), oldCertificate.getUuid().toString());
                    certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Removed from Location " + cl.getLocation().getName(), "", oldCertificate);

                    locationService.pushCertificateToLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), certificate.getUuid().toString(), pushRequest);
                    certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Pushed to Location " + cl.getLocation().getName(), "", certificate);
                }
            }

        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.FAILED, String.format("Failed to replace certificate in location %s: %s", location != null ? location.getName() : "", e.getMessage()), "", certificate);
            logger.error("Failed to replace certificate in all locations during rekey operation", e.getMessage());
            throw new CertificateOperationException("Failed to replace certificate in all locations during rekey operation: " + e.getMessage());
        }

        // notify
        try {
            logger.debug("Sending notification of certificate rekey. Certificate: {}", certificate);
            List<NotificationRecipient> recipients = NotificationRecipient.buildUserOrGroupNotificationRecipient(certificate.getOwnerUuid(), certificate.getGroupUuid());
            notificationProducer.produceNotificationCertificateActionPerformed(Resource.CERTIFICATE, certificate.getUuid(), recipients, certificate.mapToListDto(), ResourceAction.REKEY.getCode(), null);
        } catch (Exception e) {
            logger.error("Sending notification for certificate rekey failed. Certificate: {}. Error: {}", certificate, e.getMessage());
        }

        logger.debug("Certificate rekeyed: {}", certificate);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.REVOKE)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void revokeCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRevocationDto request) throws NotFoundException {
        validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.REVOKE);

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setAuthorityUuid(authorityUuid.getValue());
        actionMessage.setData(request);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserProfile().getUser().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.REVOKE);
        actionMessage.setResourceUuid(UUID.fromString(certificateUuid));
        actionMessage.setRaProfileUuid(raProfileUuid.getValue());

        actionProducer.produceMessage(actionMessage);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.REVOKE)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void revokeCertificateAction(final UUID certificateUuid, ClientCertificateRevocationDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRevokePermissions();
        }
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Revoking Certificate: ", certificate);

        CertRevocationDto caRequest = new CertRevocationDto();
        caRequest.setReason(request.getReason());
        if (request.getReason() == null) {
            caRequest.setReason(CertificateRevocationReason.UNSPECIFIED);
        }
        caRequest.setAttributes(request.getAttributes());
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(raProfile.mapToDto().getAttributes()));
        caRequest.setCertificate(certificate.getCertificateContent().getContent());
        try {
            certificateApiClient.revokeCertificate(
                    raProfile.getAuthorityInstanceReference().getConnector().mapToDto(),
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);
            certificateEventHistoryService.addEventHistory(CertificateEvent.REVOKE, CertificateEventStatus.SUCCESS, "Certificate revoked. Reason: " + request.getReason().getLabel(), "", certificate);
        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.REVOKE, CertificateEventStatus.FAILED, e.getMessage(), "", certificate);
            logger.error("Failed to revoke Certificate", e.getMessage());
            throw new CertificateOperationException("Failed to revoke certificate: " + e.getMessage());
        }

        try {
            certificate.setStatus(CertificateStatus.REVOKED);
            certificate.setRevokeAttributes(AttributeDefinitionUtils.serialize(extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getAttributes())));
            logger.debug("Certificate revoked. Proceeding to check and destroy key");

            if (certificate.getKey() != null && request.isDestroyKey()) {
                keyService.destroyKey(List.of(certificate.getKeyUuid().toString()));
            }
            certificateRepository.save(certificate);

        } catch (Exception e) {
            logger.warn(e.getMessage());
        }

        // notify
        try {
            logger.debug("Sending notification of certificate revoke. Certificate: {}", certificate);
            List<NotificationRecipient> recipients = NotificationRecipient.buildUserOrGroupNotificationRecipient(certificate.getOwnerUuid(), certificate.getGroupUuid());
            notificationProducer.produceNotificationCertificateActionPerformed(Resource.CERTIFICATE, certificate.getUuid(), recipients, certificate.mapToListDto(), ResourceAction.REVOKE.getCode(), null);
        } catch (Exception e) {
            logger.error("Sending notification for certificate revoke failed. Certificate: {}. Error: {}", certificate, e.getMessage());
        }

        logger.debug("Certificate revoked: {}", certificate);
    }

    private Certificate validateOldCertificateForOperation(String certificateUuid, String raProfileUuid, ResourceAction action) throws NotFoundException {
        Certificate oldCertificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));
        if (oldCertificate.getStatus().equals(CertificateStatus.NEW) || oldCertificate.getStatus().equals(CertificateStatus.REVOKED)) {
            throw new ValidationException(String.format("Cannot perform operation %s on certificate with status %s. Certificate: %s", action.getCode(), oldCertificate.getStatus().getLabel(), oldCertificate));
        }
        if (oldCertificate.getRaProfileUuid() == null || !oldCertificate.getRaProfileUuid().toString().equals(raProfileUuid)) {
            throw new ValidationException(String.format("Cannot perform operation %s on certificate. Existing Certificate RA profile is different than RA profile of request. Certificate: %s", action.getCode(), oldCertificate));
        }
        if (!oldCertificate.getRaProfile().getEnabled()) {
            throw new ValidationException(String.format("Cannot perform operation %s on certificate with disabled RA profile. Certificate: %s", action.getCode(), oldCertificate));
        }
        extendedAttributeService.validateLegacyConnector(oldCertificate.getRaProfile().getAuthorityInstanceReference().getConnector());

        return oldCertificate;
    }

    private Certificate validateNewCertificateForOperation(UUID certificateUuid) throws NotFoundException {
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.getStatus() != CertificateStatus.NEW) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue New certificate with status %s. Certificate: %s", certificate.getStatus().getLabel(), certificate)));
        }
        if (certificate.getRaProfile() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue New certificate with no RA Profile associated. Certificate: %s", certificate)));
        }
        if (certificate.getCertificateRequest() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue New certificate with no certificate request. Certificate: %s", certificate)));
        }
        if (certificate.getSourceCertificateUuid() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot renew certificate with no source certificate specified. Certificate: %s", certificate)));
        }

        return certificate;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid) throws ConnectorException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.listRevokeCertificateAttributes(raProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.VALIDATE)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public boolean validateRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.validateRevokeCertificateAttributes(raProfile, attributes);
    }

    private ClientCertificateDataResponseDto issueCertificateInternal(UUID certificateUuid) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException {
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.getStatus() != CertificateStatus.NEW) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue New certificate with status %s. Certificate: %s", certificate.getStatus().getLabel(), certificate)));
        }
        if (certificate.getRaProfile() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue New certificate with no RA Profile associated. Certificate: %s", certificate)));
        }
        if (certificate.getCertificateRequest() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue New certificate with no certificate request. Certificate: %s", certificate)));
        }

        CertificateSignRequestDto caRequest = new CertificateSignRequestDto();
        caRequest.setPkcs10(certificate.getCertificateRequest().getContent());
        caRequest.setAttributes(AttributeDefinitionUtils.deserializeRequestAttributes(certificate.getIssueAttributes()));
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(certificate.getRaProfile().mapToDto().getAttributes()));
        CertificateDataResponseDto issueCaResponse = certificateApiClient.issueCertificate(
                certificate.getRaProfile().getAuthorityInstanceReference().getConnector().mapToDto(),
                certificate.getRaProfile().getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                caRequest);

        logger.info("Certificate {} was issued by authority", certificateUuid);

        certificateService.issueNewCertificate(certificateUuid, issueCaResponse.getCertificateData(), issueCaResponse.getMeta());

        // notify
        try {
            logger.debug("Sending notification of certificate issue. Certificate: {}", certificate);
            List<NotificationRecipient> recipients = NotificationRecipient.buildUserOrGroupNotificationRecipient(certificate.getOwnerUuid(), certificate.getGroupUuid());
            notificationProducer.produceNotificationCertificateActionPerformed(Resource.CERTIFICATE, certificate.getUuid(), recipients, certificate.mapToListDto(), ResourceAction.ISSUE.getCode(), null);
        } catch (Exception e) {
            logger.error("Sending notification for certificate issue failed. Certificate: {}. Error: {}", certificate, e.getMessage());
        }

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData(issueCaResponse.getCertificateData());
        response.setUuid(certificate.getUuid().toString());
        return response;
    }

    /**
     * Function to parse the CSR from string to BC JCA objects
     *
     * @param pkcs10 Base64 encoded csr string
     * @return Jca object
     * @throws IOException
     */
    private JcaPKCS10CertificationRequest parseCsrToJcaObject(String pkcs10) throws IOException {
        JcaPKCS10CertificationRequest csr;
        try {
            csr = CsrUtil.csrStringToJcaObject(pkcs10);
        } catch (IOException e) {
            logger.debug("Failed to parse CSR, will decode and try again...");
            String decodedPkcs10 = new String(Base64.getDecoder().decode(pkcs10));
            csr = CsrUtil.csrStringToJcaObject(decodedPkcs10);
        }
        return csr;
    }

    /**
     * Check and get the CSR from the existing certificate
     *
     * @param certificate Old certificate
     * @return CSR from the old certificate
     */
    private String getExistingCsr(Certificate certificate) {
        if (certificate.getCertificateRequest() == null
                || certificate.getCertificateRequest().getContent() == null) {
            // If the CSR is not found for the existing certificate, then throw error
            throw new ValidationException(
                    ValidationError.create(
                            "CSR does not available for the existing certificate"
                    )
            );
        }
        return certificate.getCertificateRequest().getContent();
    }

    private UUID getTokenProfileUuid(UUID tokenProfileUuid, Certificate certificate) {
        if (certificate.getKeyUuid() == null && tokenProfileUuid == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Token Profile cannot be empty for creating new CSR"
                    )
            );
        }
        return tokenProfileUuid != null ? tokenProfileUuid : certificate.getKey().getTokenProfile().getUuid();
    }

    /**
     * Validate existing key from the old certificate
     *
     * @param keyUuid             Key UUID
     * @param signatureAttributes Signature Attributes
     * @param certificate         Existing certificate to be renewed
     * @return UUID of the key from the old certificate
     */
    private UUID existingKeyValidation(UUID keyUuid, List<RequestAttributeDto> signatureAttributes, Certificate certificate) {
        // If the signature attributes are not provided in the request and not available in the old certificate, then throw error
        final CertificateRequest certificateRequest = certificate.getCertificateRequest();
        if (signatureAttributes == null && (certificateRequest == null || certificateRequest.getSignatureAttributes() == null)) {
            throw new ValidationException(
                    ValidationError.create(
                            "Signature Attributes are not provided in request and old certificate"
                    )
            );
        }

        // If the key UUID is not provided and if the old certificate does not contain a key UUID, then throw error
        if (keyUuid == null && certificate.getKeyUuid() == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key UUID is not provided in the request and old certificate does not have key reference"
                    )
            );
        } else if (keyUuid == null && !certificate.mapToDto().isPrivateKeyAvailability()) {
            // If the status of the private key is not valid, then throw error
            throw new ValidationException(
                    "Old certificate does not have private key or private key is in incorrect state"
            );
        } else if (keyUuid != null && keyUuid.equals(certificate.getKeyUuid())) {
            throw new ValidationException(
                    ValidationError.create(
                            "Rekey operation not permitted. Cannot use same key to rekey certificate"
                    )
            );
        } else if (keyUuid != null) {
            return keyUuid;
        } else {
            throw new ValidationException(
                    ValidationError.create(
                            "Invalid key information"
                    )
            );
        }
    }

    /**
     * Generate the CSR for new certificate for issuance and renew
     *
     * @param keyUuid             UUID of the key
     * @param tokenProfileUuid    Token profile UUID
     * @param principal           X500 Principal
     * @param signatureAttributes Signature attributes
     * @return Base64 encoded CSR string
     * @throws NotFoundException When the key or tokenProfile UUID is not found
     */
    private String generateCsr(UUID keyUuid, UUID tokenProfileUuid, X500Principal principal, List<RequestAttributeDto> signatureAttributes) throws NotFoundException {
        try {
            // Generate the CSR with the above-mentioned information
            return cryptographicOperationService.generateCsr(
                    keyUuid,
                    tokenProfileUuid,
                    principal,
                    signatureAttributes
            );
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Failed to generate the CSR. Error: " + e.getMessage()
                    )
            );
        }
    }

    /**
     * Function to evaluate if the certificate and the key contains the same public key
     *
     * @param certificateContent Certificate Content
     * @param csr                CSR
     */
    private void validatePublicKeyForCsrAndCertificate(String certificateContent, String csr, boolean shouldMatch) {
        try {
            X509Certificate certificate = CertificateUtil.parseCertificate(certificateContent);
            JcaPKCS10CertificationRequest csrObject = parseCsrToJcaObject(csr);
            if (shouldMatch && !Arrays.equals(certificate.getPublicKey().getEncoded(), csrObject.getPublicKey().getEncoded())) {
                throw new Exception("Public key of certificate and CSR does not match");
            }
            if (!shouldMatch && Arrays.equals(certificate.getPublicKey().getEncoded(), csrObject.getPublicKey().getEncoded())) {
                throw new Exception("Public key of certificate and CSR are same");
            }
        } catch (Exception e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Unable to validate the public key of CSR and certificate. Error: " + e.getMessage()
                    )
            );
        }
    }


    private void validateSubjectDnForCertificate(String certificateContent, String csr) {
        try {
            X509Certificate certificate = CertificateUtil.parseCertificate(certificateContent);
            JcaPKCS10CertificationRequest csrObject = parseCsrToJcaObject(csr);
            if (!certificate.getSubjectX500Principal().getName().equals(csrObject.getSubject().toString())) {
                throw new Exception("Subject DN of certificate and CSR does not match");
            }
        } catch (Exception e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Unable to validate the Subject DN of CSR and certificate. Error: " + e.getMessage()
                    )
            );
        }
    }

    private Map<String, Object> generateCsr(String uploadedCsr, List<RequestAttributeDto> csrAttributes, UUID keyUUid, UUID tokenProfileUuid, List<RequestAttributeDto> signatureAttributes) throws NotFoundException, CertificateException {
        String pkcs10;
        String csr;
        List<DataAttribute> merged = List.of();

        if (uploadedCsr != null && !uploadedCsr.isEmpty()) {
            csr = uploadedCsr;
        } else {
            merged = AttributeDefinitionUtils.mergeAttributes(CsrAttributes.csrAttributes(), csrAttributes);
            AttributeDefinitionUtils.validateAttributes(CsrAttributes.csrAttributes(), csrAttributes);
            csr = generateCsr(
                    keyUUid,
                    tokenProfileUuid,
                    CsrUtil.buildSubject(csrAttributes),
                    signatureAttributes
            );
        }
        try {
            pkcs10 = Base64.getEncoder().encodeToString(parseCsrToJcaObject(csr).getEncoded());
        } catch (IOException e) {
            logger.debug("Failed to parse CSR: " + e);
            throw new CertificateException(e);
        }
        return Map.of("csr", pkcs10, "attributes", merged);
    }


    private void checkNewStatus(CertificateStatus status) {
        if (status.equals(CertificateStatus.NEW)) {
            throw new ValidationException(
                    ValidationError.create("Cannot perform operation on certificate with status NEW")
            );
        }
    }

}
