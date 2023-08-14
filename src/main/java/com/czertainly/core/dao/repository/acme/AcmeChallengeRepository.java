package com.czertainly.core.dao.repository.acme;

import com.czertainly.core.dao.entity.acme.AcmeChallenge;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AcmeChallengeRepository extends SecurityFilterRepository<AcmeChallenge, Long> {
    Optional<AcmeChallenge> findByUuid(UUID uuid);
    Optional<AcmeChallenge> findByChallengeId(String challengeId);
}
