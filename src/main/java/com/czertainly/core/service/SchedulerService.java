package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobDetailDto;
import com.czertainly.core.security.authz.SecurityFilter;
import org.springframework.http.ResponseEntity;

public interface SchedulerService {

    ScheduledJobsResponseDto listScheduledJobs(final SecurityFilter filter, final PaginationRequestDto pagination);

    ScheduledJobDetailDto getScheduledJobDetail(final String uuid) throws NotFoundException;

    void deleteScheduledJob(final String uuid);

    ScheduledJobHistoryResponseDto getScheduledJobHistory(final SecurityFilter filter, final PaginationRequestDto pagination, String uuid);

    void enableScheduledJob(String uuid) throws SchedulerException, NotFoundException;

    void disableScheduledJob(String uuid) throws SchedulerException, NotFoundException;

}
