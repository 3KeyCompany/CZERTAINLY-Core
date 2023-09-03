package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AcmeProfileRepository extends SecurityFilterRepository<AcmeProfile, Long> {
    Optional<AcmeProfile> findByUuid(UUID uuid);

    boolean existsByName(String name);

    @EntityGraph(attributePaths = {"raProfile"})
    AcmeProfile findByName(String name);

    List<AcmeProfile> findByRaProfile(RaProfile raProfile);
}
