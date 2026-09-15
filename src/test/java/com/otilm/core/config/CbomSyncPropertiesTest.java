package com.otilm.core.config;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CbomSyncPropertiesTest {

    @Test
    void theDocumentedDefaultsAreAccepted() {
        CbomSyncProperties p = properties(1000, Duration.ofSeconds(60), 3);
        assertThat(p.maxAttempts()).isEqualTo(4);
    }

    @Test
    void theDefaultValuesBindWhenNoPropertyIsSet() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of()));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound).isEqualTo(properties(1000, Duration.ofSeconds(60), 3));
    }

    @Test
    void aBareOverlapNumberBindsAsSeconds() {
        // Without @DurationUnit Spring reads a unitless duration as milliseconds, so CBOM_SYNC_OVERLAP=60 would bind
        // as 60 ms and toSeconds() would round it away to no overlap at all.
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.overlap", "60")));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.overlap()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void anOverlapWithAUnitSuffixStillBindsByThatUnit() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.overlap", "2m")));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.overlap()).isEqualTo(Duration.ofSeconds(120));
    }

    /**
     * The kill switch. {@code max-ingest-documents: 0} disables only the backlog pass, so it cannot stop a newly stored
     * CBOM from acquiring {@code crypto_asset_source} rows -- and a CBOM that has them cannot be deleted through the
     * API until the deletion lifecycle lands. This is the value that covers both passes.
     */
    @Test
    void assetIngestIsOnByDefaultAndCanBeTurnedOff() {
        Binder defaults = new Binder(new MapConfigurationPropertySource(Map.of()));
        assertThat(defaults.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class)).assetIngestEnabled())
                .isTrue();

        Binder off = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.asset-ingest-enabled", "false")));
        assertThat(off.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class)).assetIngestEnabled()).isFalse();
    }

    @Test
    void zeroRetryRunsMeansAFailedEntryIsWrittenOffAtOnce() {
        assertThat(properties(1, Duration.ZERO, 0).maxAttempts()).isEqualTo(1);
    }

    @Test
    void aPageSizeOutsideTheRepositoryContractIsRefused() {
        Duration overlap = Duration.ofSeconds(60);
        assertThatThrownBy(() -> properties(0, overlap, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.page-size");
        assertThatThrownBy(() -> properties(1001, overlap, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.page-size");
    }

    @Test
    void aNegativeOverlapOrRetryBudgetIsRefused() {
        Duration negative = Duration.ofSeconds(-1);
        Duration overlap = Duration.ofSeconds(60);
        assertThatThrownBy(() -> properties(1000, negative, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.overlap");
        assertThatThrownBy(() -> properties(1000, null, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.overlap");
        assertThatThrownBy(() -> properties(1000, overlap, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.skipped-retry-runs");
    }

    @Test
    void theIngestTunablesBindTheirDocumentedDefaults() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of()));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.assetBatchSize()).isEqualTo(100);
        assertThat(bound.maxIngestDocuments()).isEqualTo(50);
        assertThat(bound.ingestRetryAfter()).isEqualTo(Duration.ofMinutes(30));
    }

    @Test
    void aBareIngestRetryNumberBindsAsSecondsLikeTheOverlap() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.ingest-retry-after", "90")));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.ingestRetryAfter()).isEqualTo(Duration.ofSeconds(90));
    }

    @Test
    void anUnusableIngestBoundIsRefused() {
        Duration retryAfter = Duration.ofMinutes(30);
        assertThatThrownBy(() -> new CbomSyncProperties(1000, Duration.ZERO, 3, true, 0, 50, retryAfter))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.asset-batch-size");
        assertThatThrownBy(() -> new CbomSyncProperties(1000, Duration.ZERO, 3, true, 100, -1, retryAfter))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.max-ingest-documents");
        assertThatThrownBy(() -> new CbomSyncProperties(1000, Duration.ZERO, 3, true, 100, 50, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.ingest-retry-after");
    }

    /** The three values this test does not vary, so a new bound cannot be added without a test naming it. */
    private static CbomSyncProperties properties(int pageSize, Duration overlap, int skippedRetryRuns) {
        return new CbomSyncProperties(pageSize, overlap, skippedRetryRuns, true, 100, 50, Duration.ofMinutes(30));
    }
}
