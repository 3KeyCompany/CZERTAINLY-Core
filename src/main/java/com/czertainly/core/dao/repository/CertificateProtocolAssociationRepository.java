package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.CertificateProtocolAssociation;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateProtocolAssociationRepository extends SecurityFilterRepository<CertificateProtocolAssociation, Long> {
}
