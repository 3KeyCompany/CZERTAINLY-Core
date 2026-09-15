package com.otilm.core.cbom.ingest;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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
 * The withdrawal's control flow, without a database: how it batches, what it does when the cluster lock is contended,
 * and the one ordering a database would reveal only as an intermittent deadlock. The orphan rule itself is pinned
 * against real PostgreSQL in {@code CryptoAssetInventoryITest}, because it turns on the source rows and the alias
 * cascade that only the repository's own query reads.
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
        when(assetRepository.orphansAmong(any())).thenReturn(List.of());

        service(100).withdraw(CBOM);

        InOrder order = inOrder(synchronizer, sourceWriter);
        order.verify(synchronizer).lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
        order.verify(sourceWriter).detachCbom(asset, CBOM);
    }

    @Test
    void aContendedClusterLockWithdrawsNothingAndSaysSo() {
        sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(false);

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(0, 0, 0, false));
        verify(sourceWriter, never()).detachCbom(any(), any());
        verify(assetWriter, never()).delete(any());
    }

    /**
     * Each batch is its own slice of the list. Without the moving offset the first slice is withdrawn twice and
     * everything past it never at all, which is the data-loss shape this loop can have -- so what is asserted is what
     * each batch contained, not how many batches there were.
     */
    @Test
    void eachBatchWithdrawsItsOwnSliceOfTheLinks() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        UUID third = UUID.randomUUID();
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM)).thenReturn(List.of(first, second, third));
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(any())).thenReturn(List.of());

        service(2).withdraw(CBOM);

        verify(sourceWriter).detachCbom(first, CBOM);
        verify(sourceWriter).detachCbom(second, CBOM);
        verify(sourceWriter).detachCbom(third, CBOM);
        verify(sourceWriter, times(3)).detachCbom(any(), any());
        // One lock acquisition per batch transaction: three links at a batch size of two is two transactions.
        verify(synchronizer, times(2)).tryLock(CbomAssetIngestService.assetSyncLockKey(CBOM));

        // And the orphan question is asked about each batch's own assets: over the whole list, or over the wrong
        // slice, it would settle assets this transaction has not detached.
        ArgumentCaptor<List<UUID>> asked = ArgumentCaptor.captor();
        verify(assetRepository, times(2)).orphansAmong(asked.capture());
        assertThat(asked.getAllValues()).containsExactly(List.of(first, second), List.of(third));
    }

    /**
     * The counts are summed across batches, not taken from the last one. Nothing else exercises the accumulation: the
     * default batch size is 100 and every integration test withdraws fewer assets than that, so {@code plus} is only
     * ever called there as {@code NOTHING.plus(done)}, which is identity for any one field.
     */
    @Test
    void theCountsOfEveryBatchAreAddedUp() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM)).thenReturn(List.of(first, second));
        when(sourceWriter.detachCbom(any(), any())).thenReturn(1);
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(first)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(first, false)));
        when(assetRepository.orphansAmong(List.of(second)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(second, true)));

        CbomAssetDetachService.Withdrawal withdrawal = service(1).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(2, 1, 1, true));
    }

    /**
     * A batch that already committed stays committed. The caller is told the unit is incomplete, not that nothing
     * happened -- reporting zero here would understate what this node really did and, for the deletion lifecycle, would
     * present an irreversibly collected orphan as a withdrawal that never ran.
     */
    @Test
    void anAbandonedUnitStillReportsWhatTheCommittedBatchesDid() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM)).thenReturn(List.of(first, second));
        when(sourceWriter.detachCbom(first, CBOM)).thenReturn(1);
        when(synchronizer.tryLock(anyString())).thenReturn(true, false);
        when(assetRepository.orphansAmong(List.of(first)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(first, false)));

        CbomAssetDetachService.Withdrawal withdrawal = service(1).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 1, 0, false));
        verify(sourceWriter, never()).detachCbom(second, CBOM);
    }

    /** An asset another CBOM still sources is not returned as an orphan, so nothing settles it. */
    @Test
    void anAssetThatKeepsASourceIsLeftAlone() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(asset))).thenReturn(List.of());

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 0, 0, true));
        verify(assetWriter, never()).delete(any());
    }

    /** An orphan no alias points at is collected -- the branch the integration suite proves against a real cascade. */
    @Test
    void anOrphanNoAliasPointsAtIsCollected() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(asset)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(asset, false)));

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 1, 0, true));
        verify(assetWriter).delete(asset);
    }

    /** An orphan an alias points at is kept: deleting it would cascade the operator's merge decision away. */
    @Test
    void anOrphanAnAliasPointsAtIsKept() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(asset)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(asset, true)));

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 0, 1, true));
        verify(assetWriter, never()).delete(any());
    }

    private UUID sourcedAsset() {
        UUID asset = UUID.randomUUID();
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM)).thenReturn(List.of(asset));
        when(sourceWriter.detachCbom(asset, CBOM)).thenReturn(1);
        return asset;
    }

    private CbomAssetDetachService service(int batchSize) {
        return new CbomAssetDetachService(sourceWriter, assetWriter, sourceRepository, assetRepository, synchronizer,
                new TransactionHandler(), CbomIngestTestFixtures.properties(batchSize));
    }
}
