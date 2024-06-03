package com.czertainly.core.dao.repository;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.AttributeRelation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AttributeRelationRepository extends JpaRepository<AttributeRelation, String> {
    List<AttributeRelation> findByResourceAndAttributeDefinitionType(Resource resource, AttributeType attributeType);
    Optional<AttributeRelation> findByResourceAndAttributeDefinitionUuidAndAttributeDefinitionTypeAndAttributeDefinitionEnabled(Resource resource, UUID attributeDefinitionUuid, AttributeType attributeType, boolean enabled);
    List<AttributeRelation> findByResourceAndAttributeDefinitionTypeAndAttributeDefinitionEnabled(Resource resource, AttributeType attributeType, boolean enabled);
    void deleteByAttributeDefinitionUuid(UUID attributeDefinitionUuid);
    List<AttributeRelation> findByAttributeDefinitionUuid(UUID attributeDefinitionUuid);
}
