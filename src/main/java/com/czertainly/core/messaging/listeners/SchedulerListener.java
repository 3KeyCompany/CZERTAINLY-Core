package com.czertainly.core.messaging.listeners;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionMessage;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.core.dao.entity.ScheduledJob;
import com.czertainly.core.dao.entity.ScheduledJobHistory;
import com.czertainly.core.dao.repository.ScheduledJobHistoryRepository;
import com.czertainly.core.dao.repository.ScheduledJobsRepository;
import com.czertainly.core.messaging.configuration.RabbitMQConstants;
import com.czertainly.core.tasks.SchedulerJobProcessor;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@Transactional
public class SchedulerListener {

    private ApplicationContext applicationContext;

    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    private ScheduledJobsRepository scheduledJobsRepository;

    private static final Logger logger = LoggerFactory.getLogger(SchedulerListener.class);

    @RabbitListener(queues = RabbitMQConstants.QUEUE_SCHEDULER_NAME, messageConverter = "jsonMessageConverter", concurrency = "10")
    public void processMessage(SchedulerJobExecutionMessage schedulerMessage) {
        logger.info("Received scheduler message: {}", schedulerMessage);

        try {
            final Class<?> clazz = Class.forName(schedulerMessage.getClassToBeExecuted());
            final Object clazzObject = applicationContext.getBean(clazz);
            if (clazzObject != null && clazzObject instanceof SchedulerJobProcessor processor) {
                logger.info("Job {} is executed.", schedulerMessage.getJobName());
                final SchedulerJobProcessor schedulerJobProcessor = processor;
                schedulerJobProcessor.processTask(schedulerMessage.getJobName());
                logger.info("Job {} was processed.", schedulerMessage.getJobName());
            }

        } catch (SchedulerException | ConnectorException | ClassNotFoundException e) {
            logger.error("Unable to process the job {}", schedulerMessage.getJobName());

            final ScheduledJob scheduledJob = scheduledJobsRepository.findByJobName(schedulerMessage.getJobName());
            if (scheduledJob != null) {
                final ScheduledJobHistory scheduledJobHistory = new ScheduledJobHistory();
                scheduledJobHistory.setScheduledJobUuid(scheduledJob.getUuid());
                scheduledJobHistory.setJobExecution(new Date());
                scheduledJobHistory.setSchedulerExecutionStatus(SchedulerJobExecutionStatus.FAILED);
                scheduledJobHistoryRepository.save(scheduledJobHistory);
            } else {
                logger.error("There is no such job {} registered.", schedulerMessage.getJobName());
            }
        }
    }

    // SETTERs

    @Autowired
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Autowired
    public void setScheduledJobHistoryRepository(ScheduledJobHistoryRepository scheduledJobHistoryRepository) {
        this.scheduledJobHistoryRepository = scheduledJobHistoryRepository;
    }

    @Autowired
    public void setScheduledJobsRepository(ScheduledJobsRepository scheduledJobsRepository) {
        this.scheduledJobsRepository = scheduledJobsRepository;
    }
}
