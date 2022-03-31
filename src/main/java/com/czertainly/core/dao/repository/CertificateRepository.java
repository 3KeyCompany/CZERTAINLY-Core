package com.czertainly.core.dao.repository;

import com.czertainly.api.model.core.certificate.CertificateStatus;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.custom.CustomCertificateRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
@Transactional
public interface CertificateRepository extends JpaRepository<Certificate, Long>, CustomCertificateRepository {

    Optional<Certificate> findByUuid(String uuid);
    Optional<Certificate> findBySerialNumberIgnoreCase(String serialNumber);
    List<Certificate> findDistinctByGroupId(Long group);
    List<Certificate> findDistinctByStatus(CertificateStatus certificateStatus);
    List<Certificate> findDistinctByEntityId(Long entity);
    List<Certificate> findDistinctByRaProfileId(Long raProfile);
    List<Certificate> findByCertificateType(CertificateType certificateType);
    List<Certificate> findByKeySize(Integer keySize);
    List<Certificate> findByBasicConstraints(String basicConstraints);
    List<Certificate> findByNotAfterLessThan(Date notAfter);
    Optional<Certificate> findByIssuerSerialNumberIgnoreCase(String issuerSerialNumber);
    Optional <Certificate> findByCommonName(String commonName);
    Certificate findByCertificateContent(CertificateContent certificateContent);
	Optional<Certificate> findByFingerprint(String fingerprint);
    List<Certificate> findBySubjectDn(String subjectDn);
	List<Certificate> findAllByIssuerSerialNumber(String issuerSerialNumber);

    List<Certificate> findByStatus(CertificateStatus status);

    List<Certificate> findByRaProfile(RaProfile raProfile);
    List<Certificate> findByGroup(CertificateGroup group);
    List<Certificate> findByEntity(CertificateEntity entity);

    @Query("SELECT DISTINCT signatureAlgorithm FROM Certificate")
    List<String> findDistinctSignatureAlgorithm();
    
    @Query("SELECT DISTINCT certificateType FROM Certificate")
    List<CertificateType> findDistinctCertificateType();
    
    @Query("SELECT DISTINCT keySize FROM Certificate")
    List<Integer> findDistinctKeySize();
    
    @Query("SELECT DISTINCT basicConstraints FROM Certificate")
    List<String> findDistinctBasicConstraints();

    @Query("SELECT DISTINCT keyUsage FROM Certificate")
    List<String> findDistinctKeyUsage();
    
    @Query("SELECT DISTINCT status FROM Certificate")
    List<CertificateStatus> findDistinctStatus();

    @Query("SELECT DISTINCT publicKeyAlgorithm FROM Certificate")
    List<String> findDistinctPublicKeyAlgorithm();

    List<Certificate> findAllByOrderByIdDesc(Pageable p);

    @Modifying
    @Query("delete from Certificate u where u.id in ?1")
    void deleteCertificateWithIds(List<Long> ids);
}
