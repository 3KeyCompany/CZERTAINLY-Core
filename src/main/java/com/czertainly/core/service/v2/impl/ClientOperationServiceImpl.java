package com.czertainly.core.service.v2.impl;

import com.czertainly.api.clients.v2.CertificateApiClient;
import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.CertificateOperationException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.CertificateUpdateRAProfileDto;
import com.czertainly.api.model.client.location.PushToLocationRequestDto;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.connector.v2.CertRevocationDto;
import com.czertainly.api.model.connector.v2.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v2.CertificateRenewRequestDto;
import com.czertainly.api.model.connector.v2.CertificateSignRequestDto;
import com.czertainly.api.model.core.audit.ObjectType;
import com.czertainly.api.model.core.audit.OperationType;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.certificate.CertificateStatus;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateLocation;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.service.CertValidationService;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.LocationService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.CsrUtil;
import com.czertainly.core.util.MetaDefinitions;
import com.czertainly.core.util.ValidatorUtil;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

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

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.REQUEST)
    public List<AttributeDefinition> listIssueCertificateAttributes(String raProfileUuid) throws ConnectorException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        return extendedAttributeService.listIssueCertificateAttributes(raProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.VALIDATE)
    public boolean validateIssueCertificateAttributes(String raProfileUuid, List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        return extendedAttributeService.validateIssueCertificateAttributes(raProfile, attributes);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.ISSUE)
    public ClientCertificateDataResponseDto issueCertificate(String raProfileUuid, ClientCertificateSignRequestDto request, Boolean ignoreAuthToRa) throws ConnectorException, AlreadyExistException, CertificateException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));

        if (!ignoreAuthToRa) {
            ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        }
        extendedAttributeService.validateLegacyConnector(raProfile.getAuthorityInstanceReference().getConnector());

        CertificateSignRequestDto caRequest = new CertificateSignRequestDto();
        // the CSR should be properly converted to ensure consistent Base64-encoded format
        String pkcs10;
        try {
            pkcs10 = Base64.getEncoder().encodeToString(parseCsrToJcaObject(request.getPkcs10()).getEncoded());
        } catch (IOException e) {
            logger.debug("Failed to parse CSR: " + e);
            throw new CertificateException(e);
        }
        caRequest.setPkcs10(pkcs10);
        caRequest.setAttributes(request.getAttributes());
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(raProfile.mapToDto().getAttributes()));

        CertificateDataResponseDto caResponse = certificateApiClient.issueCertificate(
                raProfile.getAuthorityInstanceReference().getConnector().mapToDto(),
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                caRequest);

        //Certificate certificate = certificateService.checkCreateCertificate(caResponse.getCertificateData());
        Certificate certificate = certificateService.checkCreateCertificateWithMeta(caResponse.getCertificateData(), caResponse.getMeta());
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("CSR", pkcs10);
        certificateEventHistoryService.addEventHistory(CertificateEvent.ISSUE, CertificateEventStatus.SUCCESS, "Issued using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation), certificate);

        logger.info("Certificate created {}", certificate);
        CertificateUpdateRAProfileDto dto = new CertificateUpdateRAProfileDto();
        dto.setRaProfileUuid(raProfile.getUuid());
        logger.debug("Certificate : {}, RA Profile: {}", certificate, raProfile);
        certificateService.updateRaProfile(certificate.getUuid(), dto);
        certificateService.updateIssuer();
        try {
            certValidationService.validate(certificate);
        } catch (Exception e) {
            logger.warn("Unable to validate the uploaded Certificate, {}", e.getMessage());
        }

        ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData(caResponse.getCertificateData());
        response.setUuid(certificate.getUuid());
        return response;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.RENEW)
    public ClientCertificateDataResponseDto renewCertificate(String raProfileUuid, String certificateUuid, ClientCertificateRenewRequestDto request, Boolean ignoreAuthToRa) throws ConnectorException, AlreadyExistException, CertificateException, CertificateOperationException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));

        if (!ignoreAuthToRa) {
            ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        }

        Certificate oldCertificate = certificateService.getCertificateEntity(certificateUuid);
        extendedAttributeService.validateLegacyConnector(raProfile.getAuthorityInstanceReference().getConnector());
        logger.debug("Renewing Certificate: ", oldCertificate.toString());
        CertificateRenewRequestDto caRequest = new CertificateRenewRequestDto();
        // the CSR should be properly converted to ensure consistent Base64-encoded format
        String pkcs10;
        try {
            pkcs10 = Base64.getEncoder().encodeToString(parseCsrToJcaObject(request.getPkcs10()).getEncoded());
        } catch (IOException e) {
            logger.debug("Failed to parse CSR: " + e);
            throw new CertificateException(e);
        }
        caRequest.setPkcs10(pkcs10);
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(raProfile.mapToDto().getAttributes()));
        caRequest.setCertificate(oldCertificate.getCertificateContent().getContent());
        caRequest.setMeta(oldCertificate.getMeta());

        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("CSR", pkcs10);
        additionalInformation.put("Parent Certificate UUID", oldCertificate.getUuid());
        additionalInformation.put("Parent Certificate Serial Number", oldCertificate.getSerialNumber());
        Certificate certificate = null;
        CertificateDataResponseDto caResponse = null;
        try {
            caResponse = certificateApiClient.renewCertificate(
                    raProfile.getAuthorityInstanceReference().getConnector().mapToDto(),
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);
            //certificate = certificateService.checkCreateCertificate(caResponse.getCertificateData());
            certificate = certificateService.checkCreateCertificateWithMeta(caResponse.getCertificateData(), caResponse.getMeta());
            certificateEventHistoryService.addEventHistory(CertificateEvent.RENEW, CertificateEventStatus.SUCCESS, "Renewed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation), certificate);
            certificateEventHistoryService.addEventHistory(CertificateEvent.RENEW, CertificateEventStatus.SUCCESS, "Renewed using RA Profile " + raProfile.getName(), "New Certificate is issued with Serial Number: " + certificate.getSerialNumber(), oldCertificate);

            /** replace certificate in the locations if needed */
            if (request.isReplaceInLocations()) {
                logger.info("Replacing certificates in locations for certificate: " + certificate.getUuid());
                for (CertificateLocation cl : oldCertificate.getLocations()) {
                    PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
                    pushRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(cl.getPushAttributes()));

                    locationService.removeCertificateFromLocation(cl.getLocation().getUuid(), oldCertificate.getUuid());
                    certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Removed from Location " + cl.getLocation().getName(), "", oldCertificate);

                    locationService.pushCertificateToLocation(cl.getLocation().getUuid(), certificate.getUuid(), pushRequest);
                    certificateEventHistoryService.addEventHistory(CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Pushed to Location " + cl.getLocation().getName(), "", certificate);
                }
            }

        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.RENEW, CertificateEventStatus.FAILED, e.getMessage(), MetaDefinitions.serialize(additionalInformation), oldCertificate);
            logger.error("Failed to renew Certificate", e.getMessage());
            throw new CertificateOperationException("Failed to renew certificate: " + e.getMessage());
        }

        logger.info("Certificate Renewed: {}", certificate);
        CertificateUpdateRAProfileDto dto = new CertificateUpdateRAProfileDto();
        dto.setRaProfileUuid(raProfile.getUuid());
        logger.debug("Certificate : {}, RA Profile: {}", certificate, raProfile);
        certificateService.updateRaProfile(certificate.getUuid(), dto);
        certificateService.updateIssuer();
        try {
            certValidationService.validate(certificate);
        } catch (Exception e) {
            logger.warn("Unable to validate the uploaded Certificate, {}", e.getMessage());
        }

        ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData(caResponse.getCertificateData());
        response.setUuid(certificate.getUuid());
        return response;
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.REQUEST)
    public List<AttributeDefinition> listRevokeCertificateAttributes(String raProfileUuid) throws ConnectorException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        return extendedAttributeService.listRevokeCertificateAttributes(raProfile);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.ATTRIBUTES, operation = OperationType.VALIDATE)
    public boolean validateRevokeCertificateAttributes(String raProfileUuid, List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        return extendedAttributeService.validateRevokeCertificateAttributes(raProfile, attributes);
    }

    @Override
    @AuditLogged(originator = ObjectType.CLIENT, affected = ObjectType.END_ENTITY_CERTIFICATE, operation = OperationType.REVOKE)
    public void revokeCertificate(String raProfileUuid, String certificateUuid, ClientCertificateRevocationDto request, Boolean ignoreAuthToRa) throws ConnectorException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        if (!ignoreAuthToRa) {
            ValidatorUtil.validateAuthToRaProfile(raProfile.getName());
        }
        Certificate certificate = certificateService.getCertificateEntity(certificateUuid);
        extendedAttributeService.validateLegacyConnector(raProfile.getAuthorityInstanceReference().getConnector());
        logger.debug("Revoking Certificate: ", certificate.toString());

        CertRevocationDto caRequest = new CertRevocationDto();
        caRequest.setReason(request.getReason());
        caRequest.setAttributes(request.getAttributes());
        caRequest.setRaProfileAttributes(AttributeDefinitionUtils.getClientAttributes(raProfile.mapToDto().getAttributes()));
        caRequest.setCertificate(certificate.getCertificateContent().getContent());
        try {
            certificateApiClient.revokeCertificate(
                    raProfile.getAuthorityInstanceReference().getConnector().mapToDto(),
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);
            certificateEventHistoryService.addEventHistory(CertificateEvent.REVOKE, CertificateEventStatus.SUCCESS, "Certificate revoked", "", certificate);
        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(CertificateEvent.REVOKE, CertificateEventStatus.FAILED, e.getMessage(), "", certificate);
            logger.error(e.getMessage());
            throw(e);
        }
        try {
            certificate.setStatus(CertificateStatus.REVOKED);
            certificateRepository.save(certificate);
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }
    }

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
}
