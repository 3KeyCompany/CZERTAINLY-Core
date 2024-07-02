package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.CrlEntry;
import com.czertainly.core.dao.entity.CrlEntryId;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CrlEntryRepository extends SecurityFilterRepository<CrlEntry, Long> {

    Optional<CrlEntry> findById(CrlEntryId id);

}
