package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.core.web.CryptographicKeyController;
import com.czertainly.api.model.client.cryptography.key.KeyRequestDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.core.cryptography.key.KeyDetailDto;
import com.czertainly.api.model.core.cryptography.key.KeyDto;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CryptographicKeyService;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;

public class CryptographicKeyControllerImpl implements CryptographicKeyController {

    private CryptographicKeyService cryptographicKeyService;

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Override
    public List<KeyDto> listKeys(Optional<String> tokenInstanceUuid) {
        return cryptographicKeyService.listKeys(tokenInstanceUuid, SecurityFilter.create());
    }

    @Override
    public KeyDetailDto getKey(String tokenInstanceUuid, String uuid) throws NotFoundException {
        return cryptographicKeyService.getKey(SecuredParentUUID.fromString(tokenInstanceUuid), uuid);
    }

    @Override
    public KeyDetailDto createKey(String tokenInstanceUuid, KeyRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException {
        return cryptographicKeyService.createKey(SecuredParentUUID.fromString(tokenInstanceUuid), request);
    }

    @Override
    public void destroyKey(String tokenInstanceUuid, String uuid) throws ConnectorException {
        cryptographicKeyService.destroyKey(SecuredParentUUID.fromString(tokenInstanceUuid), uuid);
    }

    @Override
    public List<BaseAttribute> listCreateKeyAttributes(String tokenInstanceUuid) throws ConnectorException {
        return cryptographicKeyService.listCreateKeyAttributes(SecuredUUID.fromString(tokenInstanceUuid));
    }
}
