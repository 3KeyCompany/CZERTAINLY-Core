package com.otilm.core.dao.repository;

import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.core.dao.entity.Cbom;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CbomRepository extends SecurityFilterRepository<Cbom, UUID> {

    @Query("""
            SELECT c2
            FROM Cbom c1
            JOIN Cbom c2
                ON c1.serialNumber = c2.serialNumber
            WHERE c1.uuid = :uuid
            ORDER BY c2.version DESC
            """)
    List<Cbom> findVersionsByUuid(@Param("uuid") UUID uuid);

    boolean existsBySerialNumberAndVersion(String serialNumber, int version);

    @Query("SELECT c.uuid FROM Cbom c WHERE c.uuid IN :uuids")
    Set<UUID> findExistingUuids(@Param("uuids") List<UUID> uuids);

    /**
     * The CBOMs whose cryptographic assets have never been ingested, oldest uuid first.
     *
     * <p>
     * A header row and its assets fail independently, so the feed cannot be the only thing that offers work: it skips
     * every entry whose header already exists, which is every row a crashed ingest left behind and every CBOM uploaded
     * through Core's own API. Without this list those assets would never be ingested at all.
     */
    @Query("SELECT c FROM Cbom c WHERE c.assetSyncState = :pending ORDER BY c.uuid")
    List<Cbom> findPendingAssetIngests(@Param("pending") CbomAssetSyncState pending, Limit limit);

    /**
     * The ingest state of one CBOM, read as a scalar.
     *
     * <p>
     * A projection rather than the entity, because the ingest reads it outside any transaction to know what state its
     * claim overwrote: loading the entity here would put it in whatever persistence context is bound to the thread, and
     * the ingest's own batch transactions would then serve it from that cache.
     */
    @Query("SELECT c.assetSyncState FROM Cbom c WHERE c.uuid = :uuid")
    Optional<CbomAssetSyncState> findAssetSyncState(@Param("uuid") UUID uuid);

    /**
     * The CBOMs whose ingest is to be tried again -- {@code IN_PROGRESS} or {@code FAILED} -- longest untouched first.
     *
     * <p>
     * A row is offered again only once its last attempt is older than {@code retryBefore}: long enough that the run
     * which claimed it is gone rather than slow, and long enough that a document failing for a reason of its own is not
     * re-read every run. The ingest stamps {@code asset_sync_attempted_at} when it claims a CBOM and again when it
     * finishes, so the window is measured from the start of an attempt rather than renewed during one. A row that
     * somehow carries no attempt at all is offered rather than stranded.
     *
     * <p>
     * Kept apart from {@link #findPendingAssetIngests} rather than ordered together with it, so that the caller spends
     * its budget on never-tried documents first: a document that fails every time cannot starve the ones never tried.
     */
    @Query("""
            SELECT c FROM Cbom c
            WHERE c.assetSyncState IN :states
              AND (c.assetSyncAttemptedAt IS NULL OR c.assetSyncAttemptedAt < :retryBefore)
            ORDER BY c.assetSyncAttemptedAt NULLS FIRST, c.uuid
            """)
    List<Cbom> findAssetIngestRetries(@Param("states") Collection<CbomAssetSyncState> states,
            @Param("retryBefore") OffsetDateTime retryBefore, Limit limit);

    /**
     * Claims one CBOM of the ingest work list for this run, if it is still as the work list saw it.
     *
     * <p>
     * Selecting the list is a plain read, so two nodes whose hourly job fires in the same minute select the same rows.
     * Without a claim each then re-reads the document over HTTP and re-extracts it before the cluster lock serialises
     * the first write -- the writes converge, being idempotent upserts, but the load on the CBOM repository multiplies
     * by the number of nodes exactly when a backlog is being worked down.
     *
     * <p>
     * The guard is a compare-and-swap on what the work list read, not a state allowlist: an allowlist admitting
     * {@code IN_PROGRESS} would let the loser claim the row the winner just took. Both selectors give the caller
     * something to compare -- a {@code PENDING} row is claimed away from that state, and a retry is claimed away from
     * the {@code asset_sync_attempted_at} it was selected on, which this statement moves.
     *
     * <p>
     * A row that has never been attempted carries NULL, and both sides are folded onto {@code neverAttempted} rather
     * than compared with an IS NULL arm: a bare null parameter leaves PostgreSQL unable to infer the parameter's type,
     * and the statement fails at the driver.
     *
     * <p>
     * {@code asset_sync_error} is deliberately <b>not</b> cleared here. A claim is not an attempt: the document read it
     * pays for may answer nothing at all, and the release path can only put the state back, so clearing the reason
     * would erase the last thing an operator had to read and leave the row {@code FAILED} with no reason for a whole
     * retry window. The ingest's own {@code markInProgress} clears it at the point where an attempt genuinely starts.
     *
     * @param neverAttempted the stand-in for "no attempt yet", which the caller substitutes on both sides
     * @return 1 when this caller may proceed, 0 when another node got there first
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE Cbom c
            SET c.assetSyncState = :inProgress,
                c.assetSyncAttemptedAt = CURRENT_TIMESTAMP
            WHERE c.uuid = :uuid
              AND c.assetSyncState = :expectedState
              AND COALESCE(c.assetSyncAttemptedAt, :neverAttempted) = :expectedAttemptedAt
            """)
    int claimAssetIngest(@Param("uuid") UUID uuid, @Param("inProgress") CbomAssetSyncState inProgress,
            @Param("expectedState") CbomAssetSyncState expectedState,
            @Param("expectedAttemptedAt") OffsetDateTime expectedAttemptedAt,
            @Param("neverAttempted") OffsetDateTime neverAttempted);

    /**
     * Puts a claimed CBOM back exactly where the work list found it.
     *
     * <p>
     * A claim taken before the document read comes to nothing when the repository answers nothing at all, and a row
     * left {@code IN_PROGRESS} by an outage claims work no node is doing: it drops out of the pending list and into the
     * retry list, where it waits for {@code cbom.sync.ingest-retry-after} rather than being offered again at once.
     *
     * <p>
     * The state goes back; {@code asset_sync_attempted_at} stays where the claim put it, because an attempt really was
     * made -- the read was tried and the repository did not answer -- and that column records attempts, not successes.
     *
     * <p>
     * Guarded on {@code IN_PROGRESS}, which is the claim this caller holds: a row another node has since taken further
     * is not this run's to rewind.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE Cbom c
            SET c.assetSyncState = :previousState
            WHERE c.uuid = :uuid AND c.assetSyncState = :inProgress
            """)
    int releaseAssetIngestClaim(@Param("uuid") UUID uuid, @Param("inProgress") CbomAssetSyncState inProgress,
            @Param("previousState") CbomAssetSyncState previousState);

    /**
     * Writes the cryptographic-asset ingest state of one CBOM row.
     *
     * <p>
     * {@code error} is stored verbatim, so every caller must hand in text it shaped itself: this column is
     * operator-visible, and a driver message would carry the failing row with it.
     *
     * <p>
     * {@code expectedStates} is the state the caller believes the row is in, or null for an unconditional write. The
     * work list is selected in one transaction and acted on after an HTTP round trip, so by the time a write lands
     * another node may have finished the same CBOM: a failure written unconditionally would then flip a genuinely
     * synced row to FAILED with an error that is not about it. The write reports 0 rows in that case, which is the
     * caller's signal that its claim is stale.
     *
     * <p>
     * {@code assetSyncAttemptedAt} is stamped on every write, success or not: it is what the retry list reads to tell a
     * claim that is still live from one whose run is gone. It is set in the statement because a {@code @Modifying}
     * query bypasses dirty checking, so nothing else would set it.
     *
     * <p>
     * {@code assetsSyncedAt} records when this record last <em>succeeded</em>, so a null {@code syncedAt} leaves the
     * stored value alone rather than clearing it. Assigning it unconditionally would make a re-ingest that is merely in
     * progress -- or one that failed -- report the CBOM as never synced, while the assets from the last successful run
     * are still in the inventory and still returned by every query over them.
     *
     * <p>
     * {@code clearAutomatically}/{@code flushAutomatically}: this is a bulk update, so it bypasses the persistence
     * context. Without them a caller holding a managed {@link Cbom} keeps reading the pre-update state, and a later
     * dirty flush rewrites every column from that stale snapshot -- silently reverting the state this statement just
     * wrote, with no error. The writer's contract invites joining an ambient transaction, which is exactly the
     * composition that breaks.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE Cbom c
            SET c.assetSyncState = :state,
                c.assetSyncError = :error,
                c.assetSyncAttemptedAt = CURRENT_TIMESTAMP,
                c.assetsSyncedAt = COALESCE(:syncedAt, c.assetsSyncedAt)
            WHERE c.uuid = :uuid
              AND (:expectedStates IS NULL OR c.assetSyncState IN :expectedStates)
            """)
    int updateAssetSyncState(@Param("uuid") UUID uuid, @Param("state") CbomAssetSyncState state,
            @Param("error") String error, @Param("syncedAt") OffsetDateTime syncedAt,
            @Param("expectedStates") Collection<CbomAssetSyncState> expectedStates);
}
