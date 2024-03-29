package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.approvalprofile.ApprovalProfileRelationDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.model.auth.ResourceAction;
import jakarta.persistence.*;
import lombok.Data;

import java.util.UUID;

@Data
@Entity
@Table(name = "approval_profile_relation")
public class ApprovalProfileRelation extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_profile_uuid", insertable = false, updatable = false)
    private ApprovalProfile approvalProfile;

    @Column(name = "approval_profile_uuid")
    private UUID approvalProfileUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource")
    private Resource resource;

    @Column(name = "resource_uuid")
    private UUID resourceUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "action")
    private ResourceAction action;

    public ApprovalProfileRelationDto mapToDto() {
        final ApprovalProfileRelationDto approvalProfileRelationDto = new ApprovalProfileRelationDto();
        approvalProfileRelationDto.setUuid(this.getUuid().toString());
        approvalProfileRelationDto.setApprovalProfileUuid(this.getApprovalProfileUuid().toString());
        approvalProfileRelationDto.setResource(this.getResource());
        approvalProfileRelationDto.setResourceUuid(this.getResourceUuid());
        if (this.action != null) {
            approvalProfileRelationDto.setAction(this.getAction().getCode());
        }

        return approvalProfileRelationDto;
    }
}
