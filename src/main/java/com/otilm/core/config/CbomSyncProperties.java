package com.otilm.core.config;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;

/**
 * Tuning for the CBOM header sync against cbom-repository, bound from {@code cbom.sync.*} and validated at startup.
 *
 * <p>
 * These are deployment-time protocol parameters, not operator settings: the page size is bounded by the repository's
 * contract, and the overlap has to cover clock skew between Core and the object store plus the longest upload the
 * deployment expects (S3 stamps a multipart upload with its initiation time). The repository documents 60 s.
 *
 * @param pageSize the {@code limit} sent with {@code GET /api/v1/bom}; 1..1000 per the contract, 1000 by default
 * @param overlap how far behind the last successful run's start the next run lists from; 60 s by default. A bare number
 * binds as seconds: without {@code @DurationUnit} Spring reads it as milliseconds, so {@code 60} would silently mean 60
 * ms and the overlap would vanish
 * @param skippedRetryRuns how many later runs retry an entry that could not be stored before it is recorded as
 * permanently skipped; 3 by default, 0 writes an entry off at its first failure
 * @param assetIngestEnabled whether a run ingests cryptographic assets at all; true by default. The one switch that
 * covers <b>both</b> discovery paths -- the inline ingest of a document the run's own feed pass just stored, and the
 * backlog pass over the rows that still owe one. {@code maxIngestDocuments = 0} disables only the second, so it is not
 * a kill switch: with it at zero a newly stored CBOM still acquires {@code crypto_asset_source} rows, and a CBOM that
 * has them cannot be deleted through the API until the deletion lifecycle lands. Turning this off is what stops that
 * spreading, and it is why the value carries a deploy-time override
 * @param assetBatchSize how many assets one ingest transaction writes before committing; 100 by default. It bounds how
 * long an ingest holds the alias advisory lock and its row locks, not how much work a run does
 * @param maxIngestDocuments how many CBOMs one run ingests from the pending work list, on top of the ones its own feed
 * pass stored; 50 by default, 0 disables the pass
 * @param ingestRetryAfter how long a CBOM whose ingest is {@code IN_PROGRESS} or {@code FAILED} is left alone before a
 * run offers it again; 30 minutes by default. Measured from the start of the attempt, not from its last sign of life:
 * the ingest stamps {@code asset_sync_attempted_at} when it claims the CBOM and again when it finishes, and not in
 * between. So this has to exceed the longest single document the deployment expects to ingest, or a second run takes
 * over one that is still being written -- which costs a wasted slot and a reset claim rather than a corrupt row,
 * because the cluster lock still admits one writer at a time.
 */
@ConfigurationProperties(prefix = "cbom.sync")
public record CbomSyncProperties(@DefaultValue("1000") int pageSize,
        @DefaultValue("60s") @DurationUnit(ChronoUnit.SECONDS) Duration overlap,
        @DefaultValue("3") int skippedRetryRuns, @DefaultValue("true") boolean assetIngestEnabled,
        @DefaultValue("100") int assetBatchSize, @DefaultValue("50") int maxIngestDocuments,
        @DefaultValue("30m") @DurationUnit(ChronoUnit.SECONDS) Duration ingestRetryAfter) {

    public static final int MIN_PAGE_SIZE = 1;
    public static final int MAX_PAGE_SIZE = 1000;

    public CbomSyncProperties {
        if (pageSize < MIN_PAGE_SIZE || pageSize > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("cbom.sync.page-size must be within %d..%d, was %d"
                    .formatted(MIN_PAGE_SIZE, MAX_PAGE_SIZE, pageSize));
        }
        if (overlap == null || overlap.isNegative()) {
            throw new IllegalArgumentException("cbom.sync.overlap must be a non-negative duration, was " + overlap);
        }
        if (skippedRetryRuns < 0) {
            throw new IllegalArgumentException(
                    "cbom.sync.skipped-retry-runs must be zero or positive, was " + skippedRetryRuns);
        }
        if (assetBatchSize < 1) {
            throw new IllegalArgumentException("cbom.sync.asset-batch-size must be positive, was " + assetBatchSize);
        }
        if (maxIngestDocuments < 0) {
            throw new IllegalArgumentException(
                    "cbom.sync.max-ingest-documents must be zero or positive, was " + maxIngestDocuments);
        }
        if (ingestRetryAfter == null || ingestRetryAfter.isNegative()) {
            throw new IllegalArgumentException(
                    "cbom.sync.ingest-retry-after must be a non-negative duration, was " + ingestRetryAfter);
        }
    }

    /** The first failed attempt plus the configured retries: the attempt count at which an entry is written off. */
    public int maxAttempts() {
        return 1 + skippedRetryRuns;
    }
}
