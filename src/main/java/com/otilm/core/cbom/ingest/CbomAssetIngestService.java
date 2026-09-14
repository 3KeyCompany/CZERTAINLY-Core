package com.otilm.core.cbom.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.cbom.asset.CompositeCurve;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.pqc.PqcDecision;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import com.otilm.core.cbom.pqc.PqcRuleset;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.CryptoAssetConstraintTranslator;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ingests one CBOM's cryptographic assets as a single unit of work.
 *
 * <p>
 * The orchestrator half of the bean pair: it owns the transaction boundaries and composes the writers, and writes
 * nothing itself. {@code NOT_SUPPORTED} because a caller may hand it a document it has just fetched while its own
 * transaction is open, and because the state writes have to commit independently of the asset writes -- see below.
 *
 * <p>
 * <b>The document is a parameter, never a fetch.</b> Every caller has the document already, and taking it as an
 * argument is what keeps the HTTP read outside the transaction that holds the cluster lock.
 *
 * <p>
 * <b>Three boundaries, and why each is its own transaction.</b>
 * <ul>
 * <li>{@code markInProgress} / {@code markSynced} / {@code markFailed} run in their own transactions, because
 * {@link CbomAssetSyncStateWriter} is {@code REQUIRED} and would otherwise enrol the state in the very transaction that
 * is failing -- the failure would then roll back the record of itself, and the operator would see a CBOM that looks
 * untouched.</li>
 * <li>Each batch of asset writes runs in its own transaction and takes
 * {@link ClusterOperationSynchronizer.Operation#CBOM_ASSET_SYNC} inside it. That lock is transaction-scoped, so it is
 * released at every batch commit rather than held across the document: a second node can take it in the gap, and the
 * first node then abandons the rest of the document at its next batch. Safe, because every write is an idempotent
 * upsert and the CBOM goes on owing an ingest -- but it is why a batch is bounded by {@code cbom.sync.asset-batch-size}
 * rather than by the document.</li>
 * <li>Inside a batch, {@link CryptoAssetAliasWriter#ALIAS_DECISION_LOCK} is taken <b>before the first asset row
 * lock</b>. That lock outranks every {@code crypto_asset} row lock, so a transaction that upserts a source first and
 * stamps a guard second would deadlock against one doing the reverse.</li>
 * </ul>
 */
@Slf4j
@Service
public class CbomAssetIngestService {

    /** Shared: building one per document is measurable on a large inventory. */
    private static final ObjectMapper JSON_COLUMN = ObjectMapperFactory.jsonColumn();

    private final CbomAssetExtractor extractor;
    private final CryptoAssetWriter assetWriter;
    private final CryptoAssetSourceWriter sourceWriter;
    private final CbomAssetSyncStateWriter stateWriter;
    private final CryptoAssetRepository assetRepository;
    private final PqcEvaluator evaluator;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final TransactionHandler transactionHandler;
    private final int batchSize;

    public CbomAssetIngestService(CbomAssetExtractor extractor, CryptoAssetWriter assetWriter,
            CryptoAssetSourceWriter sourceWriter, CbomAssetSyncStateWriter stateWriter,
            CryptoAssetRepository assetRepository, PqcEvaluator evaluator,
            ClusterOperationSynchronizer clusterSynchronizer, TransactionHandler transactionHandler,
            CbomSyncProperties properties) {
        this.extractor = extractor;
        this.assetWriter = assetWriter;
        this.sourceWriter = sourceWriter;
        this.stateWriter = stateWriter;
        this.assetRepository = assetRepository;
        this.evaluator = evaluator;
        this.clusterSynchronizer = clusterSynchronizer;
        this.transactionHandler = transactionHandler;
        this.batchSize = properties.assetBatchSize();
    }

    /** What one document's ingest did, for the run report. */
    public enum IngestOutcome {
        /** Every asset the document yielded is stored and the CBOM reads {@code SYNCED}. */
        INGESTED,
        /** Another node holds the cluster lock; the CBOM is left for a later run, still owing an ingest. */
        LOCKED_ELSEWHERE,
        /** The document was refused before anything was written; the CBOM reads {@code FAILED} with the reason. */
        REFUSED,
        /** Writing failed partway; the CBOM reads {@code FAILED} and the next run redoes the unit. */
        FAILED
    }

    /**
     * Ingests the document's assets and leaves the CBOM row saying what happened. Idempotent: every write is an upsert
     * on the arbiters the migration declares, so redoing a unit a crash left half-written converges on the same rows.
     *
     * @param seenAt when this CBOM was observed to say what it says -- one constant for the whole document, because
     * {@link CryptoAssetSourceWriter#upsertSource} elects the newest <em>observation</em> and a per-asset clock would
     * make an arbitrary asset of the same document win
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public IngestOutcome ingest(UUID cbomUuid, Map<String, Object> document, OffsetDateTime seenAt) {
        final JsonNode tree = JSON_COLUMN.valueToTree(document);
        return ingest(cbomUuid, tree, seenAt);
    }

    /** As {@link #ingest(UUID, Map, OffsetDateTime)}, for a document already parsed into a tree. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public IngestOutcome ingest(UUID cbomUuid, JsonNode document, OffsetDateTime seenAt) {
        runInOwnTransaction(() -> stateWriter.markInProgress(cbomUuid));

        final CbomAssetExtractor.Extraction extraction;
        try {
            extraction = extractor.extract(document);
        } catch (RuntimeException e) {
            log.warn("CBOM asset ingest: extracting the document failed for CBOM {}", cbomUuid, e);
            return refuse(cbomUuid, "the document could not be read for cryptographic assets (see the Core log)");
        }

        if (extraction.documentScopeUnavailable()) {
            // Refused rather than ingested: without the whole-document scope a fabricated placeholder digest is
            // trusted and every certificate's public-key slot empties, which merges rows that are not the same asset.
            // An over-merge cannot be undone without re-keying the inventory; not ingesting can be retried.
            return refuse(cbomUuid,
                    "the document's cross-component scope could not be built, so its assets cannot be keyed safely");
        }

        try {
            for (List<CbomAssetExtractor.ExtractedAsset> batch : batches(extraction.assets())) {
                final boolean locked = transactionHandler
                        .runInNewTransaction(() -> writeBatchUnderClusterLock(cbomUuid, batch, seenAt));
                if (!locked) {
                    return IngestOutcome.LOCKED_ELSEWHERE;
                }
            }
        } catch (RuntimeException e) {
            log.warn("CBOM asset ingest: storing the assets failed for CBOM {}", cbomUuid, e);
            return fail(cbomUuid, "storing the cryptographic assets failed: " + safeReason(e));
        }

        runInOwnTransaction(() -> stateWriter.markSynced(cbomUuid, seenAt));
        log
                .debug("CBOM asset ingest: CBOM {} ingested {} assets, {} components skipped", cbomUuid,
                        extraction.assetCount(), extraction.skips().size());
        return IngestOutcome.INGESTED;
    }

    /**
     * One batch, inside the transaction that holds the cluster lock. Returns false when another node holds it, which is
     * a skip rather than a failure: the CBOM keeps owing an ingest and the next run offers it again.
     */
    private boolean writeBatchUnderClusterLock(UUID cbomUuid, List<CbomAssetExtractor.ExtractedAsset> batch,
            OffsetDateTime seenAt) {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.CBOM_ASSET_SYNC)) {
            return false;
        }
        // Before the first crypto_asset row lock any writer below will take. Re-entrant within the transaction, so
        // taking it here costs the writers' own acquisitions nothing.
        clusterSynchronizer.lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);

        // A set, not a list: two components of one document can key as the same asset, and the verdict pass reads
        // each row back once, after every source of the batch has been merged into it.
        final Set<UUID> written = new LinkedHashSet<>();
        for (CbomAssetExtractor.ExtractedAsset asset : batch) {
            final UUID assetUuid = assetWriter.upsertIdentity(asset.identityKey(), fieldsOf(asset), asset.guard());
            sourceWriter
                    .upsertSource(assetUuid, cbomUuid, propertiesOf(asset), asset.evidence(),
                            asset.reportedOccurrences(), seenAt);
            written.add(assetUuid);
        }
        stampVerdicts(written);
        return true;
    }

    /**
     * Stamps the PQC verdict of every asset this batch touched, reading each row back after its sources were merged.
     *
     * <p>
     * Read back rather than evaluated from the document: an asset several CBOMs report is evaluated on the payload the
     * merge elected, not on whichever document happened to arrive last. Stamping here rather than leaving the rows to
     * {@code PqcVerdictSweeper} is a latency decision -- a null {@code pqc_ruleset_version} is already stale to the
     * sweep -- and it matters most on the first ingest, when the sweep has the largest backlog it will ever have.
     */
    private void stampVerdicts(Iterable<UUID> assetUuids) {
        for (UUID assetUuid : assetUuids) {
            final CryptoAsset row = assetRepository.findById(assetUuid).orElse(null);
            if (row == null) {
                continue;
            }
            final JsonNode merged = JSON_COLUMN.valueToTree(row.getMergedCryptoProperties());
            final PqcDecision decision = evaluator
                    .evaluate(evaluator.fromStoredRow(fieldsOf(row), merged),
                            PqcEvaluator.nistQuantumSecurityLevel(merged));
            assetWriter
                    .applyPqcVerdict(assetUuid, decision.verdict(), decision.ruleId(), decision.reason(),
                            PqcRuleset.VERSION, decision.evaluatedFields());
        }
    }

    private IngestOutcome refuse(UUID cbomUuid, String reason) {
        runInOwnTransaction(() -> stateWriter.markFailed(cbomUuid, reason));
        return IngestOutcome.REFUSED;
    }

    private IngestOutcome fail(UUID cbomUuid, String reason) {
        runInOwnTransaction(() -> stateWriter.markFailed(cbomUuid, reason));
        return IngestOutcome.FAILED;
    }

    /** Where the state writes get their independence: the writer is {@code REQUIRED} and would otherwise join. */
    private void runInOwnTransaction(Runnable write) {
        transactionHandler.runInNewTransaction(write);
    }

    private List<List<CbomAssetExtractor.ExtractedAsset>> batches(List<CbomAssetExtractor.ExtractedAsset> assets) {
        final List<List<CbomAssetExtractor.ExtractedAsset>> batches = new ArrayList<>();
        for (int from = 0; from < assets.size(); from += batchSize) {
            batches.add(assets.subList(from, Math.min(from + batchSize, assets.size())));
        }
        return batches;
    }

    private static CryptoAssetIdentityFields fieldsOf(CbomAssetExtractor.ExtractedAsset asset) {
        return CryptoAssetIdentityFields
                .of(PqcEvaluator.assetTypeOf(asset.normalized().assetType()), asset.normalized());
    }

    /** The curve is joined back to the composite spelling the evaluator's rules and the identity preimage both use. */
    private static CryptoAssetIdentityFields fieldsOf(CryptoAsset row) {
        return new CryptoAssetIdentityFields(row.getAssetType(), row.getName(), row.getOid(), row.getAlgorithmFamily(),
                row.getPrimitive(), row.getParameterSet(), CompositeCurve.join(row.getCurve()), row.getMode(),
                row.getPadding(), row.getVariant());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> propertiesOf(CbomAssetExtractor.ExtractedAsset asset) {
        final JsonNode retained = asset.retainedProperties();
        return retained == null || retained.isNull() ? null : JSON_COLUMN.convertValue(retained, Map.class);
    }

    /**
     * The operator-visible half of a failure. A driver message is never it: a constraint violation's DETAIL line
     * carries the failing row, and for {@code crypto_asset} that row carries the identity key.
     */
    private static String safeReason(RuntimeException e) {
        return CryptoAssetConstraintTranslator.describe(e);
    }
}
