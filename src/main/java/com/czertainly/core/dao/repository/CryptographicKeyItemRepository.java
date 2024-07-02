package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CryptographicKeyItemRepository extends SecurityFilterRepository<CryptographicKeyItem, UUID> {

    Optional<CryptographicKeyItem> findByUuid(UUID uuid);

    Optional<CryptographicKeyItem> findByFingerprint(String fingerprint);

    Optional<CryptographicKeyItem> findByUuidAndCryptographicKey(UUID uuid, CryptographicKey cryptographicKey);

    List<CryptographicKeyItem> findByKeyReferenceUuid(UUID keyReferenceUuid);
}
