package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.ApprovalProfileVersion;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ApprovalProfileVersionRepository extends SecurityFilterRepository<ApprovalProfileVersion, UUID>  {
}
