package com.czertainly.core.dao.entity;

import com.czertainly.api.exception.NotFoundException;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Data;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@Data
@Entity
@Table(name = "approval_profile")
public class ApprovalProfile extends UniquelyIdentifiedAndAudited {

    @Column(name = "name")
    private String name;

    @Column(name = "enabled")
    private boolean enabled;

    @JsonBackReference
    @OneToMany(mappedBy = "approvalProfile", fetch = FetchType.LAZY)
    private List<ApprovalProfileVersion> approvalProfileVersions = new ArrayList<>();

    @OneToMany(mappedBy = "approvalProfile", fetch = FetchType.LAZY)
    private List<ApprovalProfileRelation> approvalProfileRelations = new ArrayList<>();

    @JsonBackReference
    public ApprovalProfileVersion getTheLatestApprovalProfileVersion() {
        return getApprovalProfileVersions().stream().max(Comparator.comparingInt(ApprovalProfileVersion::getVersion)).get();
    }

    public ApprovalProfileVersion getApprovalProfileVersionByVersion(final int version) throws NotFoundException {
        Optional<ApprovalProfileVersion> approvalProfileVersion = getApprovalProfileVersions().stream().filter(apv -> apv.getVersion() == version).findFirst();
        if (!approvalProfileVersion.isPresent()) {
            throw new NotFoundException("Unable to find approval profile version with version " + version);
        }
        return approvalProfileVersion.get();
    }

}
