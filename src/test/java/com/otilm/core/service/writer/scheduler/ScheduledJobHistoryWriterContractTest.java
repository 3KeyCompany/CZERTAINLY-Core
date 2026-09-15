package com.otilm.core.service.writer.scheduler;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Pins the one thing about the writer that a tidy-up would break: it is called from inside an {@code AFTER_COMMIT}
 * phase, where a {@code REQUIRED} write joins a transaction that has already committed and is lost. Making it a
 * {@code @Service} would have {@code TransactionalBoundaryArchTest}'s Rule D demand exactly that.
 */
class ScheduledJobHistoryWriterContractTest {

    @Test
    void everyPublicMethodOpensItsOwnTransaction() {
        assertFalse(ScheduledJobHistoryWriter.class.isAnnotationPresent(Service.class),
                "a @Service writer must be REQUIRED (Rule D), which loses the AFTER_COMMIT write");
        for (Method method : ScheduledJobHistoryWriter.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers()) || method.isSynthetic()) {
                continue;
            }
            Transactional transactional = method.getAnnotation(Transactional.class);
            assertNotNull(transactional, method.getName() + " must be @Transactional");
            assertEquals(Propagation.REQUIRES_NEW, transactional.propagation(),
                    method.getName() + " must commit on its own, whatever transaction the caller is in");
        }
    }
}
