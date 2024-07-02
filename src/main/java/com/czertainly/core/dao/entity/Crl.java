package com.czertainly.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "crl")
public class Crl extends UniquelyIdentified {

    @Column(name = "ca_certificate_uuid")
    private UUID caCertificateUuid;

    @Column(name = "issuer_dn", nullable = false)
    private String issuerDn;

    @Column(name = "serial_number", nullable = false)
    private String serialNumber;

    @Column(name = "crl_issuer_dn", nullable = false)
    private String crlIssuerDn;

    @Column(name = "crl_number", nullable = false)
    private String crlNumber;

    @Column(name = "next_update", nullable = false)
    private Date nextUpdate;

    @Column(name = "crl_number_delta")
    private String crlNumberDelta;

    @Column(name = "next_update_delta")
    private Date nextUpdateDelta;

    @Column(name = "last_revocation_date")
    private Date lastRevocationDate;

    @OneToMany(mappedBy = "crl", fetch = FetchType.LAZY)
    @JsonBackReference
    @ToString.Exclude
    private List<CrlEntry> crlEntries;

    public Map<String, CrlEntry> getCrlEntriesMap() {
        return crlEntries.stream().collect(Collectors.toMap(crlEntry -> crlEntry.getId().getSerialNumber(), crlEntry -> crlEntry));
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Crl crl = (Crl) o;
        return getUuid() != null && Objects.equals(getUuid(), crl.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
