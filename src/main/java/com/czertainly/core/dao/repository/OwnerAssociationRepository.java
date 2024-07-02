package com.czertainly.core.dao.repository;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.OwnerAssociation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface OwnerAssociationRepository extends JpaRepository<OwnerAssociation, UUID> {
    // owner associations
    OwnerAssociation findByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    long deleteByOwnerUuid(UUID ownerUuid);

    long deleteByResourceAndObjectUuidAndOwnerUuidNotNull(Resource resource, UUID objectUuid);

    long countByOwnerUuidAndResourceAndObjectUuidIn(UUID ownerUuid, Resource resource, List<UUID> objectUuids);
}
