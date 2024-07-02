package com.czertainly.core.tasks;

import com.czertainly.api.clients.SchedulerApiClient;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.scheduler.SchedulerJobDto;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.api.model.scheduler.SchedulerRequestDto;
import com.czertainly.core.dao.entity.ScheduledJob;
import com.czertainly.core.dao.entity.ScheduledJobHistory;
import com.czertainly.core.dao.repository.ScheduledJobHistoryRepository;
import com.czertainly.core.dao.repository.ScheduledJobsRepository;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.producers.NotificationProducer;
import com.czertainly.core.model.ScheduledTaskResult;
import com.czertainly.core.security.authn.CzertainlyUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;
import java.util.UUID;

public abstract class SchedulerJobProcessor {

    private Logger logger = LoggerFactory.getLogger(SchedulerJobProcessor.class);

    protected SchedulerApiClient schedulerApiClient;

    protected ScheduledJobsRepository scheduledJobsRepository;

    protected ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    private NotificationProducer notificationProducer;

    @Autowired
    public void setScheduledJobsRepository(ScheduledJobsRepository scheduledJobsRepository) {
        this.scheduledJobsRepository = scheduledJobsRepository;
    }

    @Autowired
    public void setSchedulerApiClient(SchedulerApiClient schedulerApiClient) {
        this.schedulerApiClient = schedulerApiClient;
    }

    @Autowired
    public void setScheduledJobHistoryRepository(ScheduledJobHistoryRepository scheduledJobHistoryRepository) {
        this.scheduledJobHistoryRepository = scheduledJobHistoryRepository;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    abstract String getDefaultJobName();

    abstract String getDefaultCronExpression();

    abstract boolean isDefaultOneTimeJob();

    abstract String getJobClassName();

    abstract boolean systemJob();

    abstract ScheduledTaskResult performJob(final String jobName);

    public void registerScheduler() throws SchedulerException {
        registerScheduler(getDefaultJobName(), getDefaultCronExpression(), isDefaultOneTimeJob());
    }

    public void registerScheduler(final String jobName, final String cronExpression, final boolean oneTime) throws SchedulerException {
        registerScheduler(jobName, cronExpression, oneTime, null);
    }

    public ScheduledJob registerScheduler(final String jobName, final String cronExpression, final boolean oneTime, final Object objectData) throws SchedulerException {
        final SchedulerJobDto schedulerDetail = new SchedulerJobDto(jobName, cronExpression, getJobClassName());
        schedulerApiClient.schedulerCreate(new SchedulerRequestDto(schedulerDetail));
        return saveJobDefinition(jobName, cronExpression, oneTime, objectData);
    }

    public void processTask(final String jobName) throws SchedulerException, NotFoundException {
        final ScheduledJobHistory scheduledJobHistory = registerJobHistory(jobName);
        final ScheduledTaskResult result = performJob(jobName);
        updateJobHistory(scheduledJobHistory, result);
        checkOneTimeJob(jobName, result.getStatus());
    }

    private void checkOneTimeJob(final String jobName, final SchedulerJobExecutionStatus status) throws SchedulerException {
        final ScheduledJob scheduledJob = scheduledJobsRepository.findByJobName(jobName);

        if (!scheduledJob.isSystem()) {
            notificationProducer.produceNotificationScheduledJobCompleted(Resource.SCHEDULED_JOB,
                    scheduledJob.getUuid(),
                    NotificationRecipient.buildUserNotificationRecipient(scheduledJob.getUserUuid()),
                    jobName,
                    scheduledJob.getJobType(),
                    status.getLabel());
        }

        if (SchedulerJobExecutionStatus.SUCCESS.equals(status) && scheduledJob != null && scheduledJob.isOneTime()) {
            schedulerApiClient.deleteScheduledJob(jobName);
            logger.info("Scheduled job {} was deleted/unscheduled because it was one time job only.", jobName);
        }
    }

    private ScheduledJobHistory registerJobHistory(final String jobName) throws NotFoundException {
        final ScheduledJob scheduledJob = scheduledJobsRepository.findByJobName(jobName);
        if (scheduledJob == null) {
            logger.error("There is no such job {} registered.", jobName);
            throw new NotFoundException("Scheduled job with name %s not found.".formatted(jobName));
        }

        final ScheduledJobHistory scheduledJobHistory = new ScheduledJobHistory();
        scheduledJobHistory.setScheduledJobUuid(scheduledJob.getUuid());
        scheduledJobHistory.setJobExecution(new Date());
        scheduledJobHistory.setSchedulerExecutionStatus(SchedulerJobExecutionStatus.STARTED);
        return scheduledJobHistoryRepository.save(scheduledJobHistory);
    }

    private void updateJobHistory(final ScheduledJobHistory scheduledJobHistory, final ScheduledTaskResult result) {
        scheduledJobHistory.setJobEndTime(new Date());
        scheduledJobHistory.setSchedulerExecutionStatus(result.getStatus());
        scheduledJobHistory.setResultMessage(result.getResultMessage());
        scheduledJobHistory.setResultObjectType(result.getResultObjectType());
        scheduledJobHistory.setResultObjectIdentification(result.getResultObjectIdentification());
        scheduledJobHistoryRepository.save(scheduledJobHistory);
    }

    private ScheduledJob saveJobDefinition(final String jobName, final String cronExpression, final boolean oneTime, final Object objectData) {
        ScheduledJob scheduledJob = scheduledJobsRepository.findByJobName(jobName);
        if (scheduledJob != null) {
            logger.info("Job {} was already registered.", jobName);
            return scheduledJob;
        }

        scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(jobName);
        scheduledJob.setCronExpression(cronExpression);
        scheduledJob.setObjectData(objectData);
        scheduledJob.setOneTime(oneTime);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            final String userUuid = ((CzertainlyUserDetails) authentication.getPrincipal()).getUserUuid();
            scheduledJob.setUserUuid(UUID.fromString(userUuid));
        }
        scheduledJob.setEnabled(true);
        scheduledJob.setSystem(this.systemJob());
        scheduledJob.setJobClassName(this.getJobClassName());
        scheduledJobsRepository.save(scheduledJob);
        logger.info("Scheduler job {} was registered.", jobName);

        return scheduledJob;
    }


}
