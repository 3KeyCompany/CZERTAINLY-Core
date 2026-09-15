package com.otilm.core.service.writer.scheduler;

import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.model.ScheduledTaskResult;
import java.util.Date;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short, self-committing writes to {@code scheduled_job_history}, so a job's bookkeeping never shares a transaction
 * with the job.
 *
 * <p>
 * A {@code @Component} with {@code REQUIRES_NEW} on every method rather than a {@code @Service} with {@code REQUIRED}
 * (Rule D of {@code TransactionalBoundaryArchTest}), on purpose: the same methods are called from
 * {@code SchedulerListener}, which runs with no transaction, and from an {@code AFTER_COMMIT} event handler, where a
 * {@code REQUIRED} write would join a transaction that has already committed and be lost. {@code REQUIRES_NEW} is right
 * from both call sites, and it makes a run's final status durable before any external call reports it.
 *
 * <p>
 * Each close is one {@code @Modifying} statement, as the writer convention asks, and its row count is what tells a
 * vanished row apart: the three finalizers all name the row {@link #recordStarted} committed moments earlier on the
 * same thread, so a missing row means the same thing to each of them.
 */
@Component
public class ScheduledJobHistoryWriter {

    private final ScheduledJobHistoryRepository repository;

    public ScheduledJobHistoryWriter(ScheduledJobHistoryRepository repository) {
        this.repository = repository;
    }

    /** The run has started; the row is visible to every other transaction the moment this returns. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ScheduledJobHistory recordStarted(ScheduledJob job) {
        return repository.save(newRow(job, SchedulerJobExecutionStatus.STARTED, null));
    }

    /** A run that could not start because its task class is unknown: one FAILED row, no STARTED before it. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ScheduledJobHistory recordUnknownTask(ScheduledJob job, String message) {
        return repository.save(newRow(job, SchedulerJobExecutionStatus.FAILED, message));
    }

    /** The task returned a result: closes the row with it. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFinished(UUID historyUuid, ScheduledTaskResult result) {
        close(historyUuid, result);
    }

    /**
     * The task threw: closes the row as FAILED, so it never stays STARTED forever.
     *
     * @param operatorSafeMessage text the caller shaped; it reaches the scheduler API, so never a raw exception message
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailed(UUID historyUuid, String operatorSafeMessage) {
        close(historyUuid, new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, operatorSafeMessage));
    }

    /** The task declined the run ({@code ScheduledJobSkippedException}): a skipped run leaves no history. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void removeSkipped(UUID historyUuid) {
        if (repository.removeRun(historyUuid) == 0) {
            throw vanished(historyUuid);
        }
    }

    private void close(UUID historyUuid, ScheduledTaskResult result) {
        int closed = repository
                .closeRun(historyUuid, new Date(), result.getStatus(), result.getResultMessage(),
                        result.getResultObjectType(), result.getResultObjectIdentification());
        if (closed == 0) {
            throw vanished(historyUuid);
        }
    }

    private static IllegalStateException vanished(UUID historyUuid) {
        return new IllegalStateException(
                "scheduled_job_history row " + historyUuid + " vanished before its run was finalized");
    }

    private static ScheduledJobHistory newRow(ScheduledJob job, SchedulerJobExecutionStatus status, String message) {
        ScheduledJobHistory row = new ScheduledJobHistory();
        row.setScheduledJobUuid(job.getUuid());
        row.setJobExecution(new Date());
        row.setSchedulerExecutionStatus(status);
        row.setResultMessage(message);
        return row;
    }
}
