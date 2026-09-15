package com.otilm.core.cbom.ingest;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The withdrawal's control flow, without a database: what it does when the cluster lock is contended, and the one
 * ordering a database would reveal only as an intermittent deadlock. The orphan rule itself is pinned against real
 * PostgreSQL in {@code CryptoAssetInventoryITest}, because it turns on a {@code source_count} only the recompute
 * writes.
 */
class CbomAssetDetachServiceTest {

    private static final UUID CBOM = UUID.randomUUID();

    private final CryptoAssetSourceWriter sourceWriter = mock(CryptoAssetSourceWriter.class);
    private final CryptoAssetWriter assetWriter = mock(CryptoAssetWriter.class);
    private final CryptoAssetSourceRepository sourceRepository = mock(CryptoAssetSourceRepository.class);
    private final CryptoAssetRepository assetRepository = mock(CryptoAssetRepository.class);
    private final ClusterOperationSynchronizer synchronizer = mock(ClusterOperationSynchronizer.class);

    @Test
    void theAliasLockIsTakenBeforeTheFirstAssetRowLock() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);

        service(100).withdraw(CBOM);

        InOrder order = inOrder(synchronizer, sourceWriter);
        order.verify(synchronizer).lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
        order.verify(sourceWriter).detachCbom(asset, CBOM);
    }

    @Test
    void aContendedClusterLockWithdrawsNothingAndSaysSo() {
        sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(false);

        assertThat(service(100).withdraw(CBOM)).isEmpty();

        verify(sourceWriter, never()).detachCbom(any(), any());
        verify(assetWriter, never()).delete(any());
    }

    @Test
    void linksAreWithdrawnInBatchesOfTheConfiguredSize() {
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM))
                .thenReturn(List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()));
        when(synchronizer.tryLock(anyString())).thenReturn(true);

        service(2).withdraw(CBOM);

        // One lock acquisition per batch transaction: three links at a batch size of two is two transactions.
        verify(synchronizer, times(2)).tryLock(CbomAssetIngestService.assetSyncLockKey(CBOM));
    }

    /** An asset another CBOM still sources is not even asked about: the orphan test is what the count decides. */
    @Test
    void anAssetThatKeepsASourceIsLeftAlone() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.isOrphaned(asset)).thenReturn(false);

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM).orElseThrow();

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 0, 0));
        verify(assetWriter, never()).delete(any());
        verify(assetRepository, never()).isNamedByAnAlias(any());
    }

    private UUID sourcedAsset() {
        UUID asset = UUID.randomUUID();
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM)).thenReturn(List.of(asset));
        when(sourceWriter.detachCbom(asset, CBOM)).thenReturn(1);
        return asset;
    }

    private CbomAssetDetachService service(int batchSize) {
        return new CbomAssetDetachService(sourceWriter, assetWriter, sourceRepository, assetRepository, synchronizer,
                new TransactionHandler(),
                new CbomSyncProperties(1000, Duration.ofSeconds(60), 3, true, batchSize, 50, Duration.ofMinutes(30)));
    }
}
