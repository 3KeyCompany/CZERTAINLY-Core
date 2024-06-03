package com.czertainly.core.dao.repository.workflows;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.workflows.Execution;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ExecutionRepository extends SecurityFilterRepository<Execution, UUID> {

    boolean existsByName(String name);

    @EntityGraph(attributePaths = {"actions"})
    Optional<Execution> findWithActionsByUuid(UUID uuid);

    List<Execution> findAllByResource(Resource resource);

}
