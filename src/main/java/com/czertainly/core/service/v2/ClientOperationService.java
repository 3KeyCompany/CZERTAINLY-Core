package com.czertainly.core.service.v2;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.v2.*;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;

public interface ClientOperationService {

    List<BaseAttribute> listIssueCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid
    ) throws ConnectorException;

    boolean validateIssueCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            List<RequestAttributeDto> attributes
    ) throws ConnectorException, ValidationException;

    CertificateDetailDto submitCertificateRequest(
            ClientCertificateRequestDto request
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException;

    ClientCertificateDataResponseDto issueNewCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid
    ) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException;

    ClientCertificateDataResponseDto issueCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            ClientCertificateSignRequestDto request
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException;

    void issueCertificateAction(
            final UUID certificateUuid,
            boolean isApproved
    ) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException;

    ClientCertificateDataResponseDto renewCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateRenewRequestDto request
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException;

    void renewCertificateAction(
            final UUID certificateUuid,
            ClientCertificateRenewRequestDto request,
            boolean isApproved
    ) throws NotFoundException, CertificateOperationException;

    ClientCertificateDataResponseDto rekeyCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateRekeyRequestDto request
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException;

    void rekeyCertificateAction(
            final UUID certificateUuid,
            ClientCertificateRekeyRequestDto request,
            boolean isApproved
    ) throws NotFoundException, CertificateOperationException;

    void revokeCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateRevocationDto request
    ) throws NotFoundException;

    void revokeCertificateAction(
            final UUID certificateUuid,
            ClientCertificateRevocationDto request,
            boolean isApproved
    ) throws NotFoundException, CertificateOperationException;

    List<BaseAttribute> listRevokeCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid) throws ConnectorException;

    boolean validateRevokeCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            List<RequestAttributeDto> attributes
    ) throws ConnectorException, ValidationException;
}
