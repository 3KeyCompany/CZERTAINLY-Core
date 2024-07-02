package com.czertainly.core.tasks;

import com.czertainly.api.exception.SchedulerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class ScheduledTasks {

    UpdateCertificateStatusTask updateCertificateStatusTask;

    UpdateIntuneRevocationRequestsTask updateIntuneRevocationRequestsTask;

    @Bean
    @ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
    public Void registerJobs() throws SchedulerException {
        updateCertificateStatusTask.registerScheduler();
        updateIntuneRevocationRequestsTask.registerScheduler();
        return null;
    }

    // SETTERs

    @Autowired
    public void setUpdateCertificateStatusTask(UpdateCertificateStatusTask updateCertificateStatusTask) {
        this.updateCertificateStatusTask = updateCertificateStatusTask;
    }

    @Autowired
    public void setUpdateIntuneRevocationRequestsTask(UpdateIntuneRevocationRequestsTask updateIntuneRevocationRequestsTask) {
        this.updateIntuneRevocationRequestsTask = updateIntuneRevocationRequestsTask;
    }
}
