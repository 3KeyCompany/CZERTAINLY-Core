package com.czertainly.core.dao.repository;

import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.custom.CustomCertificateRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRepository extends SecurityFilterRepository<Certificate, Long>, CustomCertificateRepository {

    @EntityGraph(attributePaths = {"certificateContent"})
    Optional<Certificate> findByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"certificateContent", "groups", "owner"})
    Optional<Certificate> findWithAssociationsByUuid(UUID uuid);

    Optional<Certificate> findBySerialNumberIgnoreCase(String serialNumber);

    Certificate findByCertificateContent(CertificateContent certificateContent);

    Optional<Certificate> findByFingerprint(String fingerprint);

    boolean existsByFingerprint(String fingerprint);

    List<Certificate> findByRaProfile(RaProfile raProfile);

    List<Certificate> findByKeyUuid(UUID keyUuid);

    List<Certificate> findBySourceCertificateUuid(UUID sourceCertificateUuid);

    @Query("SELECT DISTINCT signatureAlgorithm FROM Certificate")
    List<String> findDistinctSignatureAlgorithm();

    @Query("SELECT DISTINCT keySize FROM Certificate")
    List<Integer> findDistinctKeySize();

    @Query("SELECT DISTINCT keyUsage FROM Certificate")
    List<String> findDistinctKeyUsage();

    @Query("SELECT DISTINCT publicKeyAlgorithm FROM Certificate")
    List<String> findDistinctPublicKeyAlgorithm();

    Optional<Certificate> findByUserUuid(UUID userUuid);

    List<Certificate> findByPublicKeyFingerprint(String fingerprint);

    @Query("SELECT COUNT(*) FROM Certificate c WHERE c.certificateContentId IS NOT NULL AND c.validationStatus NOT IN :skipStatuses")
    long countCertificatesToCheckStatus(@Param("skipStatuses") List<CertificateValidationStatus> skipStatuses);

    @Query("SELECT c.uuid FROM Certificate c " +
            "WHERE c.certificateContentId IS NOT NULL AND c.validationStatus NOT IN :skipStatuses " +
            "AND (c.statusValidationTimestamp IS NULL OR c.statusValidationTimestamp <= :statusValidityEndTimestamp) " +
            "ORDER BY c.statusValidationTimestamp ASC NULLS FIRST")
    List<UUID> findCertificatesToCheckStatus(@Param("statusValidityEndTimestamp") LocalDateTime statusValidityEndTimestamp,
                                             @Param("skipStatuses") List<CertificateValidationStatus> skipStatuses,
                                             Pageable pageable);

    List<Certificate> findByComplianceResultContaining(String ruleUuid);

    List<Certificate> findByRaProfileAndComplianceStatusIsNotNull(RaProfile raProfile);

    Optional<Certificate> findBySubjectDnNormalizedAndSerialNumber(String subjectDnNormalized, String serialNumber);

    Optional<Certificate> findByIssuerDnNormalizedAndSerialNumber(String issuerDnNormalized, String serialNumber);

    List<Certificate> findBySubjectDnNormalized(String issuerDnNormalized);
}
