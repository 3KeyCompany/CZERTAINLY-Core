package com.otilm.core.cbom.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.asset.identity.CryptoAssetIdentity;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The unit of work's control flow, without a database.
 *
 * <p>
 * What is asserted here is what a CBOM row says after each way an ingest can end, and the one ordering that a database
 * would only reveal as an intermittent deadlock: the alias advisory lock is taken before the first asset row lock. The
 * extractor is the real one over the ratified tables, because a mocked extraction would only prove that the
 * orchestrator passes through whatever it is handed.
 */
class CbomAssetIngestServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final UUID CBOM = UUID.randomUUID();
    private static final OffsetDateTime SEEN_AT = OffsetDateTime.parse("2026-09-14T10:00:00Z");

    private final CryptoAssetWriter assetWriter = mock(CryptoAssetWriter.class);
    private final CryptoAssetSourceWriter sourceWriter = mock(CryptoAssetSourceWriter.class);
    private final CbomAssetSyncStateWriter stateWriter = mock(CbomAssetSyncStateWriter.class);
    private final CryptoAssetRepository assetRepository = mock(CryptoAssetRepository.class);
    private final ClusterOperationSynchronizer synchronizer = mock(ClusterOperationSynchronizer.class);

    @Test
    void everyAssetIsStoredWithItsSourceAndTheCbomReadsSynced() {
        when(synchronizer.tryLock(ClusterOperationSynchronizer.Operation.CBOM_ASSET_SYNC)).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
        verify(assetWriter, times(2)).upsertIdentity(anyString(), any(), any());
        verify(sourceWriter, times(2)).upsertSource(any(), eq(CBOM), any(), any(), anyInt(), eq(SEEN_AT));
        verify(stateWriter).markInProgress(CBOM);
        verify(stateWriter).markSynced(CBOM, SEEN_AT);
        verify(stateWriter, never()).markFailed(any(), anyString());
    }

    /**
     * The ordering the writers document and no single-threaded run can violate visibly: the advisory lock outranks
     * every {@code crypto_asset} row lock, so an ingest that took a row lock first could deadlock against a concurrent
     * alias decision. Asserted here because a database would show it only as an intermittent failure.
     */
    @Test
    void theAliasLockIsTakenBeforeTheFirstAssetRowLock() {
        when(synchronizer.tryLock(any())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        ingest(twoAlgorithms(), 100);

        InOrder order = inOrder(synchronizer, assetWriter);
        order.verify(synchronizer).lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
        order.verify(assetWriter, atLeastOnce()).upsertIdentity(anyString(), any(), any());
    }

    @Test
    void assetsAreCommittedInBatchesOfTheConfiguredSize() {
        when(synchronizer.tryLock(any())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        ingest(twoAlgorithms(), 1);

        // One lock acquisition per batch transaction, so two assets at a batch size of one is two transactions.
        verify(synchronizer, times(2)).tryLock(ClusterOperationSynchronizer.Operation.CBOM_ASSET_SYNC);
    }

    @Test
    void aContendedClusterLockLeavesTheCbomOwingAnIngest() {
        when(synchronizer.tryLock(ClusterOperationSynchronizer.Operation.CBOM_ASSET_SYNC)).thenReturn(false);

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.LOCKED_ELSEWHERE);
        verify(assetWriter, never()).upsertIdentity(anyString(), any(), any());
        verify(stateWriter, never()).markSynced(any(), any());
        verify(stateWriter, never()).markFailed(any(), anyString());
    }

    /**
     * A document with no usable scope is refused rather than ingested: with nothing refuted a fabricated digest is
     * trusted and every certificate's public-key slot empties, and both merge rows that are not the same asset. An
     * over-merge needs a re-key to undo; a refusal is retried.
     */
    @Test
    void aDocumentWhoseScopeCouldNotBeBuiltIsRefusedWithoutWritingAnything() {
        CbomAssetExtractor extractor = mock(CbomAssetExtractor.class);
        when(extractor.extract(any(JsonNode.class)))
                .thenReturn(new CbomAssetExtractor.Extraction(java.util.List.of(), java.util.List.of(), false, true));

        CbomAssetIngestService.IngestOutcome outcome = service(extractor, 100).ingest(CBOM, twoAlgorithms(), SEEN_AT);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.REFUSED);
        verify(assetWriter, never()).upsertIdentity(anyString(), any(), any());
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(stateWriter).markFailed(eq(CBOM), reason.capture());
        assertThat(reason.getValue()).contains("cross-component scope");
    }

    /**
     * The failure is recorded even though the transaction carrying the write rolled back, and what it records is text
     * this platform shaped -- never the driver's, whose DETAIL line carries the failing row and with it the identity
     * key.
     */
    @Test
    void aRefusedWriteLeavesTheCbomFailedWithTextNoDriverWrote() {
        when(synchronizer.tryLock(any())).thenReturn(true);
        when(assetWriter.upsertIdentity(anyString(), any(), any()))
                .thenThrow(new DataIntegrityViolationException(
                        "ERROR: duplicate key value violates unique constraint \"crypto_asset_identity_key_key\" "
                                + "DETAIL: Key (identity_key)=(ALG|AES|256||||) already exists."));

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.FAILED);
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(stateWriter).markFailed(eq(CBOM), reason.capture());
        assertThat(reason.getValue()).doesNotContain("identity_key").doesNotContain("DETAIL");
        verify(stateWriter, never()).markSynced(any(), any());
    }

    /**
     * The verdict is evaluated against the row the merge elected, not against the document being ingested: an asset
     * several CBOMs report has one payload, and it is not whichever document arrived last.
     */
    @Test
    void theVerdictIsStampedFromTheMergedRowRatherThanTheDocument() {
        when(synchronizer.tryLock(any())).thenReturn(true);
        UUID assetUuid = UUID.randomUUID();
        when(assetWriter.upsertIdentity(anyString(), any(), any())).thenReturn(assetUuid);
        when(assetRepository.findById(assetUuid)).thenReturn(Optional.of(mergedRsaRow()));

        ingest(oneAlgorithm(), 100);

        verify(assetWriter, times(1)).applyPqcVerdict(eq(assetUuid), any(), anyString(), anyString(), anyInt(), any());
    }

    // ---------------------------------------------------------------- fixtures

    private CbomAssetIngestService.IngestOutcome ingest(JsonNode document, int batchSize) {
        return service(realExtractor(), batchSize).ingest(CBOM, document, SEEN_AT);
    }

    private CbomAssetIngestService service(CbomAssetExtractor extractor, int batchSize) {
        return new CbomAssetIngestService(extractor, assetWriter, sourceWriter, stateWriter, assetRepository,
                new PqcEvaluator(new AssetNormalizer(IdentityTables.load())), synchronizer, new TransactionHandler(),
                properties(batchSize));
    }

    private static CbomAssetExtractor realExtractor() {
        return new CbomAssetExtractor(new CryptoAssetIdentity(new AssetNormalizer(IdentityTables.load())));
    }

    private static CbomSyncProperties properties(int assetBatchSize) {
        return new CbomSyncProperties(1000, Duration.ofSeconds(60), 3, assetBatchSize, 50, Duration.ofMinutes(30));
    }

    private void whenUpsertReturnsAFreshUuid() {
        when(assetWriter.upsertIdentity(anyString(), any(), any())).thenAnswer(call -> UUID.randomUUID());
    }

    /** A row as the database holds it after the merge, with a payload the document being ingested does not carry. */
    private static CryptoAsset mergedRsaRow() {
        CryptoAsset row = new CryptoAsset();
        row.setAssetType(CryptographicAssetType.ALGORITHM);
        row.setName("RSA-2048");
        row.setAlgorithmFamily("RSA");
        row.setParameterSet("2048");
        row
                .setMergedCryptoProperties(Map
                        .of("assetType", "algorithm", "algorithmProperties", Map.of("parameterSetIdentifier", "2048")));
        return row;
    }

    private static JsonNode oneAlgorithm() {
        return read("{\"components\":[" + algorithm("RSA-2048") + "]}");
    }

    private static JsonNode twoAlgorithms() {
        return read("{\"components\":[" + algorithm("AES-256") + "," + algorithm("RSA-2048") + "]}");
    }

    private static String algorithm(String name) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"algorithm\",\"algorithmProperties\":{}}}";
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
