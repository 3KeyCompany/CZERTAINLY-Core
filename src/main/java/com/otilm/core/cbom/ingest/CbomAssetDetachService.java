package com.otilm.core.cbom.ingest;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Withdraws one CBOM's contribution to the cryptographic asset inventory, and settles what that withdrawal leaves
 * behind.
 *
 * <p>
 * The orchestrator half of a bean pair, like {@link CbomAssetIngestService}: it owns the transaction boundaries and
 * composes the writers, and writes nothing itself.
 *
 * <p>
 * <b>The orphan rule.</b> An asset whose last source is withdrawn is deleted, unless an alias names it -- on either
 * side of a merge -- in which case the row is kept with {@code source_count} at zero and its payload cleared. The
 * inventory is meant to say what the documents currently say, and a row nothing sources any more says nothing; but an
 * alias is an operator's decision about which assets are the same asset, deleting the asset takes that decision with it
 * by cascade, and a sweep no operator asked for must not do that silently.
 *
 * <p>
 * <b>Why a batch may be abandoned.</b> Every batch takes {@link CbomAssetIngestService#assetSyncLockKey(UUID) the
 * withdrawn CBOM's asset-sync lock} and gives up when another node holds it, exactly as ingest does -- the two paths
 * write the same rows, and the lock is what keeps one node at a time on them. The key is the document's, not the
 * operation's, so a withdrawal and an unrelated document's ingest do not contend; the pair that must exclude each other
 * is this withdrawal and an ingest of the same CBOM, which share the key. Giving up is safe because the caller learns
 * it (the return value) and leaves the CBOM owing the work; it is not safe to ignore, because a half-withdrawn version
 * leaves an asset sourced by two revisions of one document at once.
 */
@Slf4j
@Service
public class CbomAssetDetachService {

    private final CryptoAssetSourceWriter sourceWriter;
    private final CryptoAssetWriter assetWriter;
    private final CryptoAssetSourceRepository sourceRepository;
    private final CryptoAssetRepository assetRepository;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final TransactionHandler transactionHandler;
    private final int batchSize;

    public CbomAssetDetachService(CryptoAssetSourceWriter sourceWriter, CryptoAssetWriter assetWriter,
            CryptoAssetSourceRepository sourceRepository, CryptoAssetRepository assetRepository,
            ClusterOperationSynchronizer clusterSynchronizer, TransactionHandler transactionHandler,
            CbomSyncProperties properties) {
        this.sourceWriter = sourceWriter;
        this.assetWriter = assetWriter;
        this.sourceRepository = sourceRepository;
        this.assetRepository = assetRepository;
        this.clusterSynchronizer = clusterSynchronizer;
        this.transactionHandler = transactionHandler;
        this.batchSize = properties.assetBatchSize();
    }

    /** What withdrawing a CBOM's contribution did, for the run report and for the tests that pin the orphan rule. */
    public record Withdrawal(int detached, int deleted, int kept) {

        static final Withdrawal NOTHING = new Withdrawal(0, 0, 0);

        Withdrawal plus(Withdrawal other) {
            return new Withdrawal(detached + other.detached, deleted + other.deleted, kept + other.kept);
        }
    }

    /**
     * Withdraws every link the given CBOM contributed, applying the orphan rule to each asset it leaves without a
     * source.
     *
     * @return empty when another node holds the cluster lock and the work was left for it -- the CBOM still sources
     * every asset it did before, and the caller must not report the withdrawal as done
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<Withdrawal> withdraw(UUID cbomUuid) {
        final List<UUID> assets = sourceRepository.findAssetUuidsByCbomUuid(cbomUuid);
        Withdrawal total = Withdrawal.NOTHING;
        for (int from = 0; from < assets.size(); from += batchSize) {
            final List<UUID> batch = assets.subList(from, Math.min(from + batchSize, assets.size()));
            final Withdrawal done = transactionHandler
                    .runInNewTransaction(() -> withdrawBatchUnderClusterLock(cbomUuid, batch));
            if (done == null) {
                return Optional.empty();
            }
            total = total.plus(done);
        }
        return Optional.of(total);
    }

    /** One batch, inside the transaction that holds the cluster lock. Null when another node holds it. */
    private Withdrawal withdrawBatchUnderClusterLock(UUID cbomUuid, List<UUID> assets) {
        if (!clusterSynchronizer.tryLock(CbomAssetIngestService.assetSyncLockKey(cbomUuid))) {
            return null;
        }
        // Before the first crypto_asset row lock, as on the ingest path: deleting an orphan deletes its aliases by
        // cascade, so this transaction may decide about aliases as well as rows.
        clusterSynchronizer.lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);

        int detached = 0;
        int deleted = 0;
        int kept = 0;
        for (UUID assetUuid : assets) {
            detached += sourceWriter.detachCbom(assetUuid, cbomUuid);
            switch (settleOrphan(assetUuid)) {
                case DELETED -> deleted++;
                case KEPT -> kept++;
                case NOT_ORPHANED -> {
                    // Another CBOM still sources it; nothing to settle.
                }
            }
        }
        return new Withdrawal(detached, deleted, kept);
    }

    private enum OrphanOutcome {
        DELETED,
        KEPT,
        NOT_ORPHANED
    }

    private OrphanOutcome settleOrphan(UUID assetUuid) {
        if (!assetRepository.isOrphaned(assetUuid)) {
            return OrphanOutcome.NOT_ORPHANED;
        }
        if (assetRepository.isNamedByAnAlias(assetUuid)) {
            log
                    .debug("CBOM asset withdrawal: asset {} has no source left but an alias names it; keeping the row",
                            assetUuid);
            return OrphanOutcome.KEPT;
        }
        assetWriter.delete(assetUuid);
        return OrphanOutcome.DELETED;
    }
}
