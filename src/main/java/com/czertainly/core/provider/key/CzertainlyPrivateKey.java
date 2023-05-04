package com.czertainly.core.provider.key;

import com.czertainly.api.model.core.connector.ConnectorDto;

import java.security.PrivateKey;

public class CzertainlyPrivateKey implements PrivateKey {

    private final String keyUuid;

    private final String tokenInstanceUuid;

    private final ConnectorDto connectorDto;

    private final String algorithm;

    public CzertainlyPrivateKey(String tokenInstanceUuid, String keyUuid, ConnectorDto connectorDto, String algorithm) {
        this.keyUuid = keyUuid;
        this.connectorDto = connectorDto;
        this.tokenInstanceUuid = tokenInstanceUuid;
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "CZERTAINLY";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    public String getKeyUuid() {
        return keyUuid;
    }

    public ConnectorDto getConnectorDto() {
        return connectorDto;
    }

    public String getTokenInstanceUuid() {
        return tokenInstanceUuid;
    }

}
