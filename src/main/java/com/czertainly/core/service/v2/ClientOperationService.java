package com.czertainly.core.service.v2;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.CertificateOperationException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;

import java.security.cert.CertificateException;
import java.util.List;

public interface ClientOperationService {

    List<AttributeDefinition> listIssueCertificateAttributes(
            String raProfileUuid) throws ConnectorException;

    boolean validateIssueCertificateAttributes(
            String raProfileUuid,
            List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException;

    ClientCertificateDataResponseDto issueCertificate(
            String raProfileUuid,
            ClientCertificateSignRequestDto request, Boolean ignoreAuthToRa) throws ConnectorException, AlreadyExistException, CertificateException;

    ClientCertificateDataResponseDto renewCertificate(
            String raProfileUuid,
            String certificateUuid,
            ClientCertificateRenewRequestDto request, Boolean ignoreAuthToRa) throws ConnectorException, AlreadyExistException, CertificateException, CertificateOperationException;

    List<AttributeDefinition> listRevokeCertificateAttributes(
            String raProfileUuid) throws ConnectorException;

    boolean validateRevokeCertificateAttributes(
            String raProfileUuid,
            List<RequestAttributeDto> attributes) throws ConnectorException, ValidationException;

    void revokeCertificate(
            String raProfileUuid,
            String certificateUuid,
            ClientCertificateRevocationDto request,
            Boolean ignoreAuthToRa) throws ConnectorException;
}
