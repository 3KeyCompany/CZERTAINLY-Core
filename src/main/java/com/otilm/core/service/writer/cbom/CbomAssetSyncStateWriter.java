package com.otilm.core.service.writer.cbom;

import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.core.dao.repository.CbomRepository;
import java.time.OffsetDateTime;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes to a CBOM row's cryptographic-asset ingest state.
 *
 * <p>
 * Kept separate from the header sync that created the row: header sync and asset ingest fail independently, and a CBOM
 * whose header is stored but whose assets could not be parsed must be visibly {@code FAILED} rather than absent -- a
 * promise that holds only if {@link #markFailed} is called from outside the transaction that failed. See its
 * documentation.
 */
@Service
public class CbomAssetSyncStateWriter {

    private final CbomRepository cbomRepository;

    public CbomAssetSyncStateWriter(CbomRepository cbomRepository) {
        this.cbomRepository = cbomRepository;
    }

    /**
     * The states a failure may be written over: everything except {@code SYNCED}.
     *
     * <p>
     * A run selects its work list, reads a document over HTTP, and only then writes. Another node can finish the same
     * CBOM inside that window, and a failure written unconditionally would flip a genuinely synced row to FAILED with
     * an error that is not about it. Success is unconditional in the other direction on purpose: the run that actually
     * ingested the assets is the one entitled to say so.
     */
    private static final Set<CbomAssetSyncState> NOT_YET_SYNCED = EnumSet
            .of(CbomAssetSyncState.PENDING, CbomAssetSyncState.IN_PROGRESS, CbomAssetSyncState.FAILED);

    /**
     * The stand-in for "never attempted", so neither side of the claim's comparison is a bare null.
     *
     * <p>
     * PostgreSQL cannot infer the type of a null bind parameter in that position and the statement fails at the driver.
     * No real attempt carries the epoch.
     */
    private static final OffsetDateTime NEVER_ATTEMPTED = OffsetDateTime.parse("1970-01-01T00:00:00Z");

    /** Claims the CBOM for an ingest attempt, clearing any error from the previous one. */
    @Transactional
    public int markInProgress(UUID cbomUuid) {
        return cbomRepository.updateAssetSyncState(cbomUuid, CbomAssetSyncState.IN_PROGRESS, null, null, null);
    }

    /**
     * Claims a CBOM off the ingest work list, only if it is still as the caller read it.
     *
     * <p>
     * For the backlog pass, which selects its list with a plain read and then spends an HTTP document read on each
     * entry: this is what stops a second node from spending the same read. {@link #markInProgress} is the unconditional
     * claim, for a caller that already holds the document and is entitled to ingest it.
     *
     * @return 1 when the caller may proceed, 0 when another node claimed the row first
     */
    @Transactional
    public int claimForIngest(UUID cbomUuid, CbomAssetSyncState expectedState, OffsetDateTime expectedAttemptedAt) {
        return cbomRepository
                .claimAssetIngest(cbomUuid, CbomAssetSyncState.IN_PROGRESS, expectedState,
                        expectedAttemptedAt == null ? NEVER_ATTEMPTED : expectedAttemptedAt, NEVER_ATTEMPTED);
    }

    /**
     * Undoes a claim whose work never happened, putting the row back in the list it came from.
     *
     * <p>
     * For the one case where the claim buys nothing: the CBOM repository answered no document read of the run at all,
     * which is not a verdict on any document. See {@link #claimForIngest}.
     */
    @Transactional
    public int releaseClaim(UUID cbomUuid, CbomAssetSyncState previousState) {
        return cbomRepository.releaseAssetIngestClaim(cbomUuid, CbomAssetSyncState.IN_PROGRESS, previousState);
    }

    @Transactional
    public int markSynced(UUID cbomUuid, OffsetDateTime syncedAt) {
        return cbomRepository.updateAssetSyncState(cbomUuid, CbomAssetSyncState.SYNCED, null, syncedAt, null);
    }

    /**
     * Records a failed ingest attempt.
     *
     * <p>
     * Call it only after the ingest transaction has rolled back. Every method on this writer is {@code REQUIRED}, by
     * the rule that a writer joins the transaction it is handed, so calling this one from inside the failing
     * transaction enrolls the FAILED row in that rollback: the state is lost, and nothing reports that it was lost. The
     * class promise above -- that a failure is visibly FAILED rather than absent -- is a promise the caller keeps, not
     * one this bean can enforce. Owning that boundary is the ingest orchestrator's job.
     *
     * @param operatorSafeError text the caller shaped itself. It is stored verbatim and shown to an operator, so a
     * driver or framework message must never be passed here: a constraint violation's {@code DETAIL} line carries the
     * failing row, and for {@code crypto_asset} that row carries the identity key. Use
     * {@code CryptoAssetConstraintTranslator} to derive a safe sentence from a database failure.
     *
     * @return 1 if the failure was recorded, 0 if the CBOM had been synced in the meantime -- see
     * {@link #NOT_YET_SYNCED}
     */
    @Transactional
    public int markFailed(UUID cbomUuid, String operatorSafeError) {
        return cbomRepository
                .updateAssetSyncState(cbomUuid, CbomAssetSyncState.FAILED, operatorSafeError, null, NOT_YET_SYNCED);
    }
}
