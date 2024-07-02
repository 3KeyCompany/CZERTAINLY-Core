package com.czertainly.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 Embedded class for a composite primary key
 */
@Setter
@Getter
@ToString
@RequiredArgsConstructor
@AllArgsConstructor
@Embeddable
public class CertificateLocationId implements Serializable {

    @Column(name = "location_uuid")
    private UUID locationUuid;

    @Column(name = "certificate_uuid")
    private UUID certificateUuid;

}