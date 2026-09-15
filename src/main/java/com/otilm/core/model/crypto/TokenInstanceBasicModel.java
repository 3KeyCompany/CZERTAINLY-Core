package com.otilm.core.model.crypto;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import java.util.UUID;

public interface TokenInstanceBasicModel {
    UUID uuid();

    String tokenInstanceUuid();

    String name();

    TokenInstanceStatus status();

    String kind();

    UUID connectorUuid();

    String connectorName();

    UUID connectorInterfaceUuid();

    long tokenProfileCount();

    default int providerInterfaceVersion() {
        return connectorInterfaceUuid() == null ? 1 : 2;
    }
}
