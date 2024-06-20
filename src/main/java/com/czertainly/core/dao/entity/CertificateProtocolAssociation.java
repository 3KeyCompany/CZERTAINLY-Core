package com.czertainly.core.dao.entity;

import com.czertainly.api.model.core.enums.Protocol;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@Setter
@Table(name = "certificate_protocol_association")
public class CertificateProtocolAssociation extends UniquelyIdentified {

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    @Column(name = "protocol", nullable = false)
    @Enumerated(EnumType.STRING)
    private Protocol protocol;

    @Column(name = "protocol_profile_uuid", nullable = false)
    private UUID protocolProfileUuid;

    @Column(name = "additional_protocol_uuid")
    private UUID additionalProtocolUuid;




}
