package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthorityInstanceReferenceRepository extends SecurityFilterRepository<AuthorityInstanceReference, Long> {

    Optional<AuthorityInstanceReference> findByUuid(UUID uuid);

    Optional<AuthorityInstanceReference> findByName(String name);
}
