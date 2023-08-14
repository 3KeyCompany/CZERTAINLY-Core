package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface Connector2FunctionGroupRepository extends SecurityFilterRepository<Connector2FunctionGroup, Long> {

	List<Connector2FunctionGroup> findAllByConnector(Connector connector);

    Optional<Connector2FunctionGroup> findByConnectorAndFunctionGroup(Connector connector, FunctionGroup functionGroup);
}
