package com.czertainly.core.dao.repository.scep;

import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.entity.scep.ScepTransaction;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScepTransactionRepository extends SecurityFilterRepository<ScepTransaction, UUID> {
    Optional<ScepProfile> findByUuid(UUID uuid);

    boolean existsByTransactionIdAndScepProfile(String transactionId, ScepProfile scepProfile);

    Optional<ScepTransaction> findByTransactionId(String transactionId);

    Optional<ScepTransaction> findByTransactionIdAndScepProfile(String transactionId, ScepProfile scepProfile);
}
