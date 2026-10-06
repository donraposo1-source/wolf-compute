# WOLF_COMPOSIO hospitality skills — executable definitions

## WOLF_INVOICE_INGEST
Input: document_ref, supplier_hint?, authority_envelope
Compose: Google Drive read/export -> OCR.space -> deterministic normalization -> Supabase write only if authority explicitly allows
Output: supplier, invoice_id, issue_date, currency, lines[], taxes, totals, source_hash, unknown_fields, provenance, mutation_performed
Fail closed: unreadable OCR/ambiguous totals/currency -> UNKNOWN; no DB write without authority.

## WOLF_SUPPLIER_PRICE_IMPACT
Input: normalized invoice lines, historical_price_snapshot, recipe_cost_map
Compose: deterministic SKU matching -> previous/current unit price -> delta -> affected recipe cost -> margin impact
Output: item_deltas[], affected_recipes[], gross_margin_delta, severity, unknown_fields, provenance
No LLM required for arithmetic/economic admission.

## WOLF_MARGIN_WATCH
Input: product_cost_snapshot, selling_prices, thresholds
Compose: current weighted cost -> contribution margin -> threshold evaluation -> ntfy/Gmail only if authority envelope explicitly permits alert mutation
Output: products_at_risk[], margin_before, margin_after, alert_candidate, alert_sent=false by default.

## WOLF_HOSPITALITY_DOCUMENT_INGEST
Input: document_ref, document_type?, authority_envelope
Compose: Drive -> OCR.space -> deterministic classification/normalization -> Sheets/Supabase only when authorized
Supported targets: invoice, supplier_price_list, recipe_technical_sheet, stock_count, receipt.
Output: document_type, normalized_records, evidence_hash, unknown_fields, provenance, mutation_performed.
