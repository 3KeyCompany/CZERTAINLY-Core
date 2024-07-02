package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.MetaDefinitions;
import com.czertainly.core.util.SerializationUtil;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.proxy.HibernateProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "certificate")
public class Certificate extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<CertificateDetailDto> {

    private static final String EMPTY_COMMON_NAME = "<empty>";

    @Serial
    private static final long serialVersionUID = -3048734620156664554L;

    private static final Logger logger = LoggerFactory.getLogger(Certificate.class);

    @Column(name = "common_name")
    private String commonName;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(name = "issuer_common_name")
    private String issuerCommonName;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_content_id", insertable = false, updatable = false)
    @ToString.Exclude
    private CertificateContent certificateContent;

    @Column(name = "certificate_content_id")
    private Long certificateContentId;

    @Column(name = "issuer_dn")
    private String issuerDn;

    @Column(name = "issuer_dn_normalized")
    private String issuerDnNormalized;

    @Column(name = "subject_dn")
    private String subjectDn;

    @Column(name = "subject_dn_normalized")
    private String subjectDnNormalized;

    @Column(name = "not_before")
    private Date notBefore;

    @Column(name = "not_after")
    private Date notAfter;

    @Column(name = "public_key_algorithm")
    private String publicKeyAlgorithm;

    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;

    @Column(name = "extended_key_usage")
    private String extendedKeyUsage;

    @Column(name = "key_usage")
    private String keyUsage;

    @Column(name = "basic_constraints")
    private String basicConstraints;

    @Column(name = "state")
    @Enumerated(EnumType.STRING)
    private CertificateState state;

    @Column(name = "validation_status")
    @Enumerated(EnumType.STRING)
    private CertificateValidationStatus validationStatus;

    @Column(name = "fingerprint")
    private String fingerprint;

    @Column(name = "public_key_fingerprint")
    private String publicKeyFingerprint;

    @Column(name = "subject_alternative_names")
    private String subjectAlternativeNames;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false, updatable = false),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false)
    )
    @SQLJoinTableRestriction("resource = 'CERTIFICATE'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uuid", referencedColumnName = "object_uuid", insertable = false, updatable = false)
    @SQLRestriction("resource = 'CERTIFICATE'")
    @ToString.Exclude
    private OwnerAssociation owner;

    @Column(name = "status_validation_timestamp")
    private LocalDateTime statusValidationTimestamp;

    @OneToMany(mappedBy = "certificate", fetch = FetchType.LAZY
            //orphanRemoval = true
    )
    @JsonBackReference
    @ToString.Exclude
    private Set<CertificateLocation> locations = new HashSet<>();

    @Column(name = "key_size")
    private Integer keySize;

    @Column(name = "certificate_type")
    @Enumerated(EnumType.STRING)
    private CertificateType certificateType;

    @Column(name = "issuer_serial_number")
    private String issuerSerialNumber;

    @Column(name = "issuer_certificate_uuid")
    private UUID issuerCertificateUuid;

    @Column(name = "certificate_validation_result", length = 100000)
    private String certificateValidationResult;

    @Column(name = "compliance_result")
    private String complianceResult;

    @Column(name = "compliance_status")
    @Enumerated(EnumType.STRING)
    private ComplianceStatus complianceStatus;

    @JsonBackReference
    @OneToMany(mappedBy = "certificate", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<CertificateEventHistory> eventHistories = new HashSet<>();

    @Column(name = "user_uuid")
    private UUID userUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CryptographicKey key;

    @Column(name = "key_uuid")
    private UUID keyUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_request_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CertificateRequestEntity certificateRequestEntity;

    @Column(name = "certificate_request_uuid")
    private UUID certificateRequestUuid;

    @Column(name = "source_certificate_uuid")
    private UUID sourceCertificateUuid;

    @Column(name = "trusted_ca")
    private Boolean trustedCa;

    @Override
    public CertificateDetailDto mapToDto() {
        final CertificateDetailDto dto = new CertificateDetailDto();
        dto.setCommonName(commonName != null ? commonName : EMPTY_COMMON_NAME);
        dto.setIssuerCommonName(getIssuerCommonNameToDto());
        if (certificateContent != null) {
            dto.setCertificateContent(certificateContent.getContent());
            dto.setIssuerDn(issuerDn);
            dto.setNotBefore(notBefore);
            dto.setNotAfter(notAfter);
            dto.setBasicConstraints(basicConstraints);
            dto.setExtendedKeyUsage(MetaDefinitions.deserializeArrayString(extendedKeyUsage));
            dto.setKeyUsage(MetaDefinitions.deserializeArrayString(keyUsage));
            dto.setFingerprint(fingerprint);
            dto.setSubjectAlternativeNames(MetaDefinitions.deserialize(subjectAlternativeNames));
            dto.setIssuerSerialNumber(issuerSerialNumber);
            dto.setSerialNumber(serialNumber);
        }
        dto.setSourceCertificateUuid(sourceCertificateUuid);
        dto.setSubjectDn(subjectDn);
        dto.setPublicKeyAlgorithm(CertificateUtil.getAlgorithmFriendlyName(publicKeyAlgorithm));
        dto.setSignatureAlgorithm(CertificateUtil.getAlgorithmFriendlyName(signatureAlgorithm));
        dto.setKeySize(keySize);
        dto.setUuid(uuid.toString());
        dto.setState(state);
        dto.setValidationStatus(validationStatus);
        dto.setCertificateType(certificateType);
        dto.setTrustedCa(trustedCa);
        if (issuerCertificateUuid != null) dto.setIssuerCertificateUuid(issuerCertificateUuid.toString());
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user understandable
         * format and send it. It is not moved into the mapToDto function, as the computation involves other repositories
         * like complianceRules etc., So only the overall status of the compliance will be set in the mapToDto function
         */
        dto.setComplianceStatus(complianceStatus);

        if (raProfile != null) {
            SimplifiedRaProfileDto raDto = new SimplifiedRaProfileDto();
            raDto.setName(raProfile.getName());
            raDto.setUuid(raProfile.getUuid().toString());
            raDto.setEnabled(raProfile.getEnabled());
            if (raProfile.getAuthorityInstanceReference() != null) {
                raDto.setAuthorityInstanceUuid(raProfile.getAuthorityInstanceReference().getUuid().toString());
            }
            dto.setRaProfile(raDto);
        }

        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }

        //Check and assign private key availability
        dto.setPrivateKeyAvailability(false);

        if (this.certificateRequestEntity != null) {
            final CertificateRequestDto certificateRequestDto = new CertificateRequestDto();
            certificateRequestDto.setContent(this.certificateRequestEntity.getContent());
            certificateRequestDto.setCertificateType(this.certificateRequestEntity.getCertificateType());
            certificateRequestDto.setCommonName(this.certificateRequestEntity.getCommonName());
            certificateRequestDto.setSubjectDn(this.certificateRequestEntity.getSubjectDn());
            certificateRequestDto.setSignatureAlgorithm(this.certificateRequestEntity.getSignatureAlgorithm());
            certificateRequestDto.setPublicKeyAlgorithm(this.certificateRequestEntity.getPublicKeyAlgorithm());
            certificateRequestDto.setCertificateRequestFormat(this.certificateRequestEntity.getCertificateRequestFormat());
            certificateRequestDto.setSubjectAlternativeNames(MetaDefinitions.deserialize(this.certificateRequestEntity.getSubjectAlternativeNames()));
            dto.setCertificateRequest(certificateRequestDto);
        }
        if (key != null && !key.getItems().isEmpty()) {
            if (!key.getItems().stream().filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE)).toList().isEmpty()) {
                dto.setPrivateKeyAvailability(true);
            }
        }
        if (key != null) dto.setKey(key.mapToDto());
        return dto;
    }

    public CertificateDto mapToListDto() {
        CertificateDto dto = new CertificateDto();
        dto.setCommonName(commonName != null ? commonName : EMPTY_COMMON_NAME);
        dto.setIssuerCommonName(getIssuerCommonNameToDto());
        dto.setSerialNumber(serialNumber);
        dto.setIssuerCommonName(issuerCommonName);
        dto.setIssuerDn(issuerDn);
        dto.setSubjectDn(subjectDn);
        dto.setNotBefore(notBefore);
        dto.setNotAfter(notAfter);
        dto.setPublicKeyAlgorithm(CertificateUtil.getAlgorithmFriendlyName(publicKeyAlgorithm));
        dto.setSignatureAlgorithm(CertificateUtil.getAlgorithmFriendlyName(signatureAlgorithm));
        dto.setKeySize(keySize);
        dto.setUuid(uuid.toString());
        dto.setState(state);
        dto.setValidationStatus(validationStatus);
        dto.setFingerprint(fingerprint);
        dto.setTrustedCa(trustedCa);
        if (issuerCertificateUuid != null) dto.setIssuerCertificateUuid(issuerCertificateUuid.toString());
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        dto.setCertificateType(certificateType);
        dto.setIssuerSerialNumber(issuerSerialNumber);
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user understandable
         * format and send it. It is not moved into the mapToDto function, as the computation involves other repositories
         * like complianceRules etc., So only the overall status of the compliance will be set in the mapToDto function
         */
        dto.setComplianceStatus(complianceStatus);

        if (raProfile != null) {
            SimplifiedRaProfileDto raDto = new SimplifiedRaProfileDto();
            raDto.setName(raProfile.getName());
            raDto.setUuid(raProfile.getUuid().toString());
            raDto.setEnabled(raProfile.getEnabled());
            if (raProfile.getAuthorityInstanceReference() != null) {
                raDto.setAuthorityInstanceUuid(raProfile.getAuthorityInstanceReference().getUuid().toString());
            }
            dto.setRaProfile(raDto);
        }

        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }

        //Check and assign private key availability
        dto.setPrivateKeyAvailability(false);
        if (key != null && !key.getItems().isEmpty()) {
            if (!key.getItems().stream().filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE)).toList().isEmpty()) {
                dto.setPrivateKeyAvailability(true);
            }
        }
        return dto;
    }

    public CertificateRequestEntity prepareCertificateRequest(final CertificateRequestFormat certificateRequestFormat) {
        final CertificateRequestEntity certificateRequestEntity = new CertificateRequestEntity();
        certificateRequestEntity.setCertificateType(this.certificateType);
        certificateRequestEntity.setKeyUsage(this.keyUsage);
        certificateRequestEntity.setCommonName(this.commonName);
        certificateRequestEntity.setPublicKeyAlgorithm(this.publicKeyAlgorithm);
        certificateRequestEntity.setSignatureAlgorithm(this.signatureAlgorithm);
        certificateRequestEntity.setSubjectAlternativeNames(this.subjectAlternativeNames);
        certificateRequestEntity.setSubjectDn(this.subjectDn);
        certificateRequestEntity.setCertificateRequestFormat(certificateRequestFormat);
        return certificateRequestEntity;
    }

    public void setCertificateContent(CertificateContent certificateContent) {
        this.certificateContent = certificateContent;
        if (certificateContent != null) this.certificateContentId = certificateContent.getId();
        else this.certificateContentId = null;
    }

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if (raProfile != null) this.raProfileUuid = raProfile.getUuid();
        else this.raProfileUuid = null;
    }

    public CertificateComplianceStorageDto getComplianceResult() {
        if (complianceResult == null) {
            return null;
        }
        return (CertificateComplianceStorageDto) SerializationUtil.deserialize(complianceResult, CertificateComplianceStorageDto.class);
    }

    public void setComplianceResult(CertificateComplianceStorageDto complianceResult) {
        this.complianceResult = SerializationUtil.serialize(complianceResult);
    }

    public void setKey(CryptographicKey key) {
        this.key = key;
        if (key != null) this.keyUuid = uuid;
    }

    public Long getValidity() {
        return TimeUnit.DAYS.convert(Math.abs(notAfter.getTime() - notBefore.getTime()), TimeUnit.MILLISECONDS);
    }

    public Long getExpiryInDays() {
        return TimeUnit.DAYS.convert(Math.abs(notAfter.getTime() - new Date().getTime()), TimeUnit.MILLISECONDS);
    }

    public CertificateRequestEntity getCertificateRequest() {
        return certificateRequestEntity;
    }

    public void setCertificateRequest(CertificateRequestEntity certificateRequestEntity) {
        this.certificateRequestEntity = certificateRequestEntity;
    }


    private String getIssuerCommonNameToDto() {
        if (issuerCommonName != null) {
            return issuerCommonName;
        } else if (issuerCertificateUuid != null) {
            return EMPTY_COMMON_NAME;
        }
        return null;
    }

    public void setTrustedCa(boolean trustedCa) {
        this.trustedCa = trustedCa;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Certificate that = (Certificate) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
