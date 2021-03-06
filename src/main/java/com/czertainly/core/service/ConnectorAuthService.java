package com.czertainly.core.service;

import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.ResponseAttributeDto;
import com.czertainly.api.model.core.connector.AuthType;

import java.util.List;
import java.util.Set;

public interface ConnectorAuthService {
    Set<AuthType> getAuthenticationTypes();

    List<AttributeDefinition> getAuthAttributes(AuthType authenticationType);

    boolean validateAuthAttributes(AuthType authenticationType, List<RequestAttributeDto> attributes);

    List<AttributeDefinition> mergeAndValidateAuthAttributes(AuthType authenticationType, List<ResponseAttributeDto> attributes);

    List<AttributeDefinition> getBasicAuthAttributes();

    Boolean validateBasicAuthAttributes(List<RequestAttributeDto> attributes);

    List<AttributeDefinition> getCertificateAttributes();

    Boolean validateCertificateAttributes(List<RequestAttributeDto> attributes);

    List<AttributeDefinition> getApiKeyAuthAttributes();

    Boolean validateApiKeyAuthAttributes(List<RequestAttributeDto> attributes);

    List<AttributeDefinition> getJWTAuthAttributes();

    Boolean validateJWTAuthAttributes(List<RequestAttributeDto> attributes);
}
