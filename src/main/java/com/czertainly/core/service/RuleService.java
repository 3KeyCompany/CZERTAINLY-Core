package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.entity.workflows.TriggerHistoryRecord;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface RuleService {

    List<ConditionDto> listConditions(Resource resource);
    ConditionDto getCondition(String conditionUuid) throws NotFoundException;
    ConditionDto createCondition(ConditionRequestDto request) throws AlreadyExistException;
    ConditionDto updateCondition(String conditionUuid, UpdateConditionRequestDto request) throws NotFoundException;
    void deleteCondition(String conditionUuid) throws NotFoundException;

    List<RuleDto> listRules(Resource resource);
    RuleDetailDto getRule(String ruleUuid) throws NotFoundException;
    RuleDetailDto createRule(RuleRequestDto request) throws AlreadyExistException, NotFoundException;
    RuleDetailDto updateRule(String ruleUuid, UpdateRuleRequestDto request) throws NotFoundException;
    void deleteRule(String ruleUuid) throws NotFoundException;
}
