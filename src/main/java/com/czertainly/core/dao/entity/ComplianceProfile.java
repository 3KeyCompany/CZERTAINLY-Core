package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.compliance.SimplifiedComplianceProfileDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.compliance.*;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Compliance Profile entity storing the details of rules and groups associated with the compliance profile.
 * It also holds the manyToMany relation with the RA Profile as they can have more than 1 RA Profile and vice versa
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_profile")
public class ComplianceProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<ComplianceProfileDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @JsonBackReference
    @OneToMany(mappedBy = "complianceProfile", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<ComplianceProfileRule> complianceRules = new HashSet<>();

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "compliance_profile_2_compliance_group",
            joinColumns = @JoinColumn(name = "profile_uuid"),
            inverseJoinColumns = @JoinColumn(name = "group_uuid"))
    @ToString.Exclude
    private Set<ComplianceGroup> groups = new HashSet<>();

    @JsonBackReference
    @ManyToMany(mappedBy = "complianceProfiles", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<RaProfile> raProfiles = new HashSet<>();

    @Override
    public ComplianceProfileDto mapToDto(){
        ComplianceProfileDto complianceProfileDto = new ComplianceProfileDto();
        complianceProfileDto.setName(name);
        complianceProfileDto.setDescription(description);
        complianceProfileDto.setUuid(uuid.toString());
        complianceProfileDto.setRaProfiles(raProfiles.stream().map(RaProfile::mapToDtoSimplified).collect(Collectors.toList()));
        Map<String, List<ComplianceRulesDto>> rules = new HashMap<>();
        //Frame a map with the Unique ID as Connector UUID, Name and Kind. This will later than be used to group the response
        for(ComplianceProfileRule complianceRule: complianceRules){
            ComplianceRule rul = complianceRule.getComplianceRule();
            String ruleKey = rul.getConnector().getUuid() + ":" + rul.getConnector().getName() + ":" + rul.getKind();
            rules.computeIfAbsent(ruleKey, k -> new ArrayList<>()).add(complianceRule.mapToDtoForProfile());
        }

        List<ComplianceConnectorAndRulesDto> rulesDtos = new ArrayList<>();
        for(Map.Entry<String, List<ComplianceRulesDto>> entry : rules.entrySet()){
            ComplianceConnectorAndRulesDto complianceConnectorAndRulesDto = new ComplianceConnectorAndRulesDto();
            String[] nameSplits = entry.getKey().split(":");
            complianceConnectorAndRulesDto.setConnectorName(nameSplits[1]);
            complianceConnectorAndRulesDto.setKind(nameSplits[2]);
            complianceConnectorAndRulesDto.setConnectorUuid(nameSplits[0]);
            complianceConnectorAndRulesDto.setRules(entry.getValue());
            rulesDtos.add(complianceConnectorAndRulesDto);
        }
        complianceProfileDto.setRules(rulesDtos);

        Map<String, List<ComplianceGroupsDto>> locGroups = new HashMap<>();
        for(ComplianceGroup complianceGroup: groups){
            String groupKey = complianceGroup.getConnector().getUuid() + ":" + complianceGroup.getConnector().getName() + ":" + complianceGroup.getKind();
            ComplianceGroupsDto uuidDto = new ComplianceGroupsDto();
            uuidDto.setUuid(complianceGroup.getUuid().toString());
            uuidDto.setName(complianceGroup.getName());
            uuidDto.setDescription(complianceGroup.getDescription());
            locGroups.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(uuidDto);
        }
        List<ComplianceConnectorAndGroupsDto> groupsDtos = new ArrayList<>();
        for(Map.Entry<String, List<ComplianceGroupsDto>> entry : locGroups.entrySet()){
            ComplianceConnectorAndGroupsDto grps = new ComplianceConnectorAndGroupsDto();
            String[] nameSplits = entry.getKey().split(":");
            grps.setConnectorName(nameSplits[1]);
            grps.setKind(nameSplits[2]);
            grps.setConnectorUuid(nameSplits[0]);
            grps.setGroups(entry.getValue());
            groupsDtos.add(grps);
        }
        complianceProfileDto.setGroups(groupsDtos);

        return complianceProfileDto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }


    public SimplifiedComplianceProfileDto raProfileMapToDto(){
        SimplifiedComplianceProfileDto complianceProfileDto = new SimplifiedComplianceProfileDto();
        complianceProfileDto.setName(name);
        complianceProfileDto.setDescription(description);
        complianceProfileDto.setUuid(uuid.toString());
        return complianceProfileDto;
    }

    /**
     *MapToDto function concentrating on providing the values that are required only for the List API
     * @return ComplianceProfilesListDto with the response for listing operation
     */
    public ComplianceProfilesListDto ListMapToDTO(){
        ComplianceProfilesListDto complianceProfileDto = new ComplianceProfilesListDto();
        complianceProfileDto.setName(name);
        complianceProfileDto.setUuid(uuid.toString());
        complianceProfileDto.setDescription(description);

        Map<String, Integer> providerGroupSummary = new HashMap<>();
        Map<String, Integer> providerGroupSummaryRules = new HashMap<>();
        for(ComplianceGroup grp : groups){
            String connectorName = grp.getConnector().getName();
            if(providerGroupSummary.containsKey(connectorName)){
                providerGroupSummary.put(connectorName, providerGroupSummary.get(connectorName) + 1);
            } else {
                providerGroupSummary.put(connectorName, 1);
            }
            List<Set<ComplianceRule>>  listRules = groups.stream().map(ComplianceGroup::getRules).toList();
            if(!listRules.isEmpty()){
                Integer listRulesSize = listRules.stream().filter(Objects::nonNull).flatMap(Set::stream).collect(Collectors.toSet()).size();
                providerGroupSummaryRules.put(connectorName, listRulesSize);
            }else {
                providerGroupSummaryRules.put(connectorName, 0);
            }
        }

        Map<String, Integer> providerSummary = new HashMap<>();
        if(complianceRules != null && complianceRules.isEmpty()) {
            for(String connectorName : providerGroupSummaryRules.keySet()) {
                providerSummary.put(connectorName, providerGroupSummaryRules.getOrDefault(connectorName, 1));
            }
        } else {
            assert complianceRules != null;
            for (ComplianceProfileRule complianceRule : complianceRules) {
                String connectorName = complianceRule.getComplianceRule().getConnector().getName();
                if (providerSummary.containsKey(connectorName)) {
                    providerSummary.put(connectorName, providerSummary.get(connectorName) + 1);
                } else {
                    providerSummary.put(connectorName, providerGroupSummaryRules.getOrDefault(connectorName, 1));
                }
            }
        }

        List<ComplianceProviderSummaryDto> complianceProviderSummaryDtoList = new ArrayList<>();
        for(String connectorName : providerSummary.keySet()){
            ComplianceProviderSummaryDto complianceProviderSummaryDto = new ComplianceProviderSummaryDto();
            complianceProviderSummaryDto.setConnectorName(connectorName);
            complianceProviderSummaryDto.setNumberOfRules(providerSummary.get(connectorName));
            complianceProviderSummaryDto.setNumberOfGroups(providerGroupSummary.get(connectorName));
            complianceProviderSummaryDtoList.add(complianceProviderSummaryDto);
        }
        complianceProfileDto.setRules(complianceProviderSummaryDtoList);
        return complianceProfileDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ComplianceProfile that = (ComplianceProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
