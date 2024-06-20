package com.czertainly.core.api.v2.client;

import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.core.client.v2.ClientOperationController;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.core.v2.*;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.v2.ClientOperationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

@RestController("clientOperationControllerV2")
public class ClientOperationControllerImpl implements ClientOperationController {

    @Autowired
    private ClientOperationService clientOperationService;

    @Override
    public List<BaseAttribute> listIssueCertificateAttributes(
            String authorityUuid,
            String raProfileUuid) throws ConnectorException {
        return clientOperationService.listIssueCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    public void validateIssueCertificateAttributes(
            String authorityUuid,
            String raProfileUuid,
            List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException {
        clientOperationService.validateIssueCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), attributes);
    }

    @Override
    public ClientCertificateDataResponseDto issueNewCertificate(
            String authorityUuid,
            String raProfileUuid,
            String certificateUuid) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException {
        return clientOperationService.issueRequestedCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), certificateUuid);
    }

    @Override
    public ClientCertificateDataResponseDto issueCertificate(
            String authorityUuid,
            String raProfileUuid,
            ClientCertificateSignRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException {
        return clientOperationService.issueCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), request, null, null, null);
    }

    @Override
    public ClientCertificateDataResponseDto renewCertificate(
            String authorityUuid,
            String raProfileUuid,
            String certificateUuid,
            ClientCertificateRenewRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException {
        return clientOperationService.renewCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), certificateUuid, request);
    }

    @Override
    public ClientCertificateDataResponseDto rekeyCertificate(
            String authorityUuid,
            String raProfileUuid,
            String certificateUuid,
            ClientCertificateRekeyRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException {
        return clientOperationService.rekeyCertificate(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid),
                certificateUuid,
                request
        );
    }

    @Override
    public List<BaseAttribute> listRevokeCertificateAttributes(
            String authorityUuid,
            String raProfileUuid) throws ConnectorException {
        return clientOperationService.listRevokeCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    public void validateRevokeCertificateAttributes(
            String authorityUuid,
            String raProfileUuid,
            List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException {
        clientOperationService.validateRevokeCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), attributes);
    }

    @Override
    public void revokeCertificate(
            String authorityUuid,
            String raProfileUuid,
            String certificateUuid,
            ClientCertificateRevocationDto request) throws ConnectorException, AttributeException {
        clientOperationService.revokeCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), certificateUuid, request);
    }
}