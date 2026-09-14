-- When the cryptographic-asset ingest last touched this CBOM, success or not.
--
-- `assets_synced_at` records the last success, so it cannot answer the question a run actually asks: has this row been
-- untouched long enough that retrying it is not stealing work from a live ingest, or re-reading a document that just
-- failed? The `cbom` table is not audited (it carries no `i_upd`), so there is no existing column that moves on every
-- attempt.
--
-- Null means never attempted, which is what every row holds today: nothing has ever ingested assets.
ALTER TABLE "cbom"
    ADD COLUMN "asset_sync_attempted_at" TIMESTAMPTZ;

-- The retry list reads (state, attempted_at) together and orders by the timestamp; the existing state index alone
-- leaves the ordering to a sort over every pending row.
CREATE INDEX "idx_cbom_asset_sync_attempt" ON "cbom" ("asset_sync_state", "asset_sync_attempted_at");
