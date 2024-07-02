package com.czertainly.core.dao.entity;

import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.core.util.AttributeDefinitionUtils;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "certificate_location")
public class CertificateLocation implements Serializable {

    @EmbeddedId
    private CertificateLocationId id = new CertificateLocationId();

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("locationUuid")
    @ToString.Exclude
    private Location location;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("certificateUuid")
    @ToString.Exclude
    private Certificate certificate;

    @Column(name = "push_attributes")
    private String pushAttributes;

    @Column(name = "csr_attributes")
    private String csrAttributes;

    @Column(name = "with_key")
    private boolean withKey;

    public List<DataAttribute> getPushAttributes() {
        return AttributeDefinitionUtils.deserialize(pushAttributes, DataAttribute.class);
    }

    public void setPushAttributes(List<DataAttribute> pushAttributes) {
        this.pushAttributes = AttributeDefinitionUtils.serialize(pushAttributes);
    }

    public List<DataAttribute> getCsrAttributes() {
        return AttributeDefinitionUtils.deserialize(csrAttributes, DataAttribute.class);
    }

    public void setCsrAttributes(List<DataAttribute> csrAttributes) {
        this.csrAttributes = AttributeDefinitionUtils.serialize(csrAttributes);
    }

    public OffsetDateTime getCreated() {return certificate.getCreated();}

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CertificateLocation that = (CertificateLocation) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public final int hashCode() {
        return Objects.hash(id);
    }
}
