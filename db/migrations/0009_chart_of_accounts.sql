-- 0009_chart_of_accounts.sql
-- The platform's chart of accounts, and the helper that lazily opens the
-- per-seller subsidiary accounts.
--
-- Reading this file tells you exactly where money sits at every instant, which
-- is the whole point of keeping a journal for a business that never holds funds:
--   * provider_clearing  - captured at the PSP, not yet split out
--   * seller_payable     - owed to a seller, awaiting the protection window
--   * seller_reserve     - withheld against chargeback exposure
--   * *_payable (tax)    - collected on behalf of an authority, owed onward
--   * commission_income  - the platform's own revenue
--   * psp_fee_expense    - the processing cost the platform absorbs

-- open_platform_account is idempotent so the migration can be re-run safely.
CREATE OR REPLACE FUNCTION open_ledger_account(
  p_code TEXT, p_name TEXT, p_kind ledger_account_kind,
  p_currency currency_code, p_owner_type TEXT DEFAULT 'platform', p_owner_id UUID DEFAULT NULL
) RETURNS UUID
LANGUAGE plpgsql AS $$
DECLARE
  v_id UUID;
  v_normal ledger_normal_balance;
BEGIN
  v_normal := CASE WHEN p_kind IN ('asset','expense') THEN 'debit'::ledger_normal_balance
                   ELSE 'credit'::ledger_normal_balance END;

  INSERT INTO ledger_accounts (id, code, name, kind, normal_balance, currency, owner_type, owner_id)
  VALUES (gen_random_uuid(), p_code, p_name, p_kind, v_normal, p_currency, p_owner_type, p_owner_id)
  ON CONFLICT (code) DO NOTHING;

  SELECT id INTO v_id FROM ledger_accounts WHERE code = p_code;
  RETURN v_id;
END;
$$;

-- Platform-level accounts, INR.
SELECT open_ledger_account('platform.clearing.razorpay',      'Provider clearing - Razorpay',            'asset',     'INR', 'provider');
SELECT open_ledger_account('platform.clearing.bridge',        'Provider clearing - bridge collection',   'asset',     'INR', 'provider');
SELECT open_ledger_account('platform.clearing.mor',           'Provider clearing - merchant of record',  'asset',     'INR', 'provider');
SELECT open_ledger_account('platform.bank.operating',         'Operating bank account',                  'asset',     'INR');
SELECT open_ledger_account('platform.receivable.psp',         'Receivable from payment provider',        'asset',     'INR');
SELECT open_ledger_account('platform.input_credit.gst',       'GST input tax credit',                    'asset',     'INR');

SELECT open_ledger_account('platform.payable.seller_control', 'Seller payable (control)',                'liability', 'INR');
SELECT open_ledger_account('platform.payable.gst_output',     'GST payable on commission (output tax)',  'liability', 'INR', 'tax_authority');
SELECT open_ledger_account('platform.payable.tcs',            'TCS payable under s.52 CGST',             'liability', 'INR', 'tax_authority');
SELECT open_ledger_account('platform.payable.tds_194o',       'TDS payable under s.194-O',               'liability', 'INR', 'tax_authority');
SELECT open_ledger_account('platform.payable.buyer_refunds',  'Refunds payable to buyers',               'liability', 'INR');
SELECT open_ledger_account('platform.payable.reserve_control','Rolling reserve held (control)',          'liability', 'INR');

SELECT open_ledger_account('platform.income.commission',      'Platform commission income',              'income',    'INR');
SELECT open_ledger_account('platform.income.other',           'Other platform income',                   'income',    'INR');

SELECT open_ledger_account('platform.expense.psp_fee',        'Payment processing fees',                 'expense',   'INR');
SELECT open_ledger_account('platform.expense.chargeback_loss','Chargeback losses absorbed',              'expense',   'INR');
SELECT open_ledger_account('platform.expense.refund_absorbed','Refund costs absorbed by the platform',   'expense',   'INR');
SELECT open_ledger_account('platform.expense.payout_fee',     'Payout transfer fees',                    'expense',   'INR');
SELECT open_ledger_account('platform.expense.writeoff',       'Uncollectible settlement offsets',        'expense',   'INR');

SELECT open_ledger_account('platform.equity.opening',         'Opening balance equity',                  'equity',    'INR');

-- Mark the control accounts so nothing can post to them directly.
UPDATE ledger_accounts SET is_control = TRUE
 WHERE code IN ('platform.payable.seller_control', 'platform.payable.reserve_control');

-- USD mirror for the global phase. The same codes with a currency suffix keep
-- the chart readable and stop a cross-currency posting by construction: an
-- entry in USD simply cannot reference an INR account.
SELECT open_ledger_account('platform.clearing.mor.usd',      'Provider clearing - MoR (USD)',       'asset',     'USD', 'provider');
SELECT open_ledger_account('platform.income.commission.usd', 'Platform commission income (USD)',    'income',    'USD');
SELECT open_ledger_account('platform.expense.psp_fee.usd',   'Payment processing fees (USD)',       'expense',   'USD');
SELECT open_ledger_account('platform.payable.seller_control.usd', 'Seller payable control (USD)',   'liability', 'USD');
UPDATE ledger_accounts SET is_control = TRUE WHERE code = 'platform.payable.seller_control.usd';

-- ---------------------------------------------------------------------------
-- Per-seller subsidiary accounts
--
-- Opened on demand the first time a seller earns anything, so the chart does
-- not carry rows for sellers who never transact.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION seller_ledger_account(p_seller_id UUID, p_purpose TEXT, p_currency currency_code)
RETURNS UUID
LANGUAGE plpgsql AS $$
DECLARE
  v_code TEXT;
  v_name TEXT;
  v_id   UUID;
BEGIN
  IF p_purpose NOT IN ('payable', 'reserve') THEN
    RAISE EXCEPTION 'unknown seller account purpose %', p_purpose USING ERRCODE = 'P0001';
  END IF;

  v_code := 'seller.' || replace(p_seller_id::text, '-', '') || '.' || p_purpose || '.' || lower(p_currency);
  SELECT id INTO v_id FROM ledger_accounts WHERE code = v_code;
  IF v_id IS NOT NULL THEN
    RETURN v_id;
  END IF;

  v_name := CASE p_purpose
              WHEN 'payable' THEN 'Seller payable'
              WHEN 'reserve' THEN 'Seller rolling reserve'
            END || ' - ' || p_seller_id::text || ' (' || p_currency || ')';

  RETURN open_ledger_account(v_code, v_name, 'liability', p_currency, 'seller', p_seller_id);
END;
$$;

COMMENT ON FUNCTION seller_ledger_account IS
  'Returns (opening on first use) a seller subsidiary account. Liability: the platform records what is owed, it never holds the funds.';
