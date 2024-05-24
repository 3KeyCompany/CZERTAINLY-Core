package com.czertainly.core.dao.repository.workflows;


import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface TriggerHistoryRepository extends SecurityFilterRepository<TriggerHistory, UUID> {

    List<TriggerHistory> findAllByTriggerUuidAndTriggerAssociationObjectUuid(UUID triggerUuid, UUID triggerAssociationObjectUuid);

}
