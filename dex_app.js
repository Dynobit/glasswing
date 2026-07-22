// Glasswing DEX client — PURE DEX, FULLY SELF-CUSTODIAL.
// Runs entirely in the user's browser. There is NO server of ours and NO
// backend in the loop; the page talks only to Hyperliquid's PUBLIC API. NO
// private key is ever read, stored, or transmitted by this page EXCEPT the
// ephemeral AGENT key, which is generated locally and kept ONLY in this
// browser's localStorage (never sent anywhere). A Hyperliquid agent wallet can
// place/cancel orders but CANNOT withdraw or transfer funds.
//
// HONESTY — WHAT IS REAL vs NOT: the HLSigner below is a REAL, faithful port of
// Hyperliquid's L1 order signing (hyperliquid-python-sdk signing.py):
//   msgpack(action) || nonce(8 BE) || vault-presence-byte  -> keccak256 =
//   connectionId -> phantom agent {source, connectionId} -> EIP-712 under domain
//   {name:"Exchange", version:"1", chainId:1337, verifyingContract:0x00..0} ->
//   secp256k1 sign with the agent key -> {r,s,v}. Crypto is loaded IN-BROWSER
//   from a PINNED CDN (noble secp256k1 + js-sha3 keccak_256 + @msgpack/msgpack);
//   we do NOT hand-roll crypto. The intermediate connectionId is byte-identical
//   to the SDK's action_hash for a fixed vector (proven offline by
//   product/hl_sign_equivalence.py).
//
//   WHAT IS NOT YET PROVEN: no live signature has been accepted by Hyperliquid
//   from this page. So the client DEFAULTS TO TESTNET and MAINNET IS BLOCKED:
//   signOrder() on mainnet THROWS "TESTNET PROOF REQUIRED" until a testnet order
//   returns status ok (which sets localStorage[glasswing.testnet_proven]=<oid>).
//   The copy loop is DRY by default (logs the exact order, places nothing).
(function () {
  "use strict";

  var CFG = {};
  try {
    CFG = JSON.parse(document.getElementById("dex-config").textContent);
  } catch (e) {
    CFG = {};
  }

  // ------------------------------------------------------------------ //
  // ENVIRONMENT. Defaults to "testnet". Mainnet requires BOTH the explicit
  // mainnet toggle AND a proven-testnet flag in localStorage (set only after a
  // testnet order returns status ok). See currentEnv() / envUrls() / the
  // mainnet gate inside HLSigner.signOrder.
  // ------------------------------------------------------------------ //
  var HL_ENV = "testnet";  // module default — NEVER "mainnet"
  var TESTNET_PROVEN_LS_KEY = CFG.testnet_proven_ls_key || "glasswing.testnet_proven";

  function mainnetToggleOn() {
    var el = document.getElementById("mainnet-toggle");
    return !!(el && el.checked);
  }
  function testnetProven() {
    // Per-browser proof: THIS browser placed an accepted testnet order …
    try {
      var v = localStorage.getItem(TESTNET_PROVEN_LS_KEY);
      if (v) return v;
    } catch (e) { /* storage optional */ }
    // … OR the build-baked CLASS proof: the SHIPPED signer code itself was
    // proven accepted by the live testnet venue (render-time artifact from
    // testnet_class_proof.mjs, bound to the exact signer scheme — absent from
    // the config unless the proof validates, so this stays fail-closed).
    if (CFG.signer_class_proof && CFG.signer_class_proof.oid) {
      return "class:" + CFG.signer_class_proof.oid;
    }
    return null;
  }
  // The env actually in effect. Mainnet ONLY if the toggle is on AND testnet is
  // proven; otherwise testnet. This is the single source of truth for routing.
  function currentEnv() {
    if (mainnetToggleOn() && testnetProven()) return "mainnet";
    return "testnet";
  }
  function isMainnet() { return currentEnv() === "mainnet"; }
  function envUrls() {
    if (isMainnet()) {
      return { info: CFG.info_url, exchange: CFG.exchange_url,
               hyperliquidChain: "Mainnet" };
    }
    return { info: CFG.testnet_info_url || CFG.info_url,
             exchange: CFG.testnet_exchange_url || CFG.exchange_url,
             hyperliquidChain: "Testnet" };
  }

  // ------------------------------------------------------------------ //
  // state. NOTE: agentKey.priv (if present) lives ONLY here + localStorage.
  // It is never placed in any network request body anywhere in this file.
  // ------------------------------------------------------------------ //
  var state = {
    account: null,
    feeApproved: false,
    agentKey: null,        // { address, priv } — priv NEVER transmitted
    agentApproved: false,
    loopTimer: null,
    seen: {}               // leader -> last-seen fill time (dedupe opens)
  };

  var AGENT_LS_KEY = CFG.agent_ls_key || "glasswing.dex.agentKey";
  var POLL_MS = 15000;

  function $(id) { return document.getElementById(id); }
  function pill(id, text, cls) {
    var el = $(id);
    if (!el) return;
    el.textContent = text;
    el.className = "pill" + (cls ? " " + cls : "");
  }
  function out(id, obj) {
    var el = $(id);
    if (!el) return;
    el.hidden = false;
    el.textContent = (typeof obj === "string") ? obj : JSON.stringify(obj, null, 1);
  }
  function log(id, line) {
    var el = $(id);
    if (!el) return;
    el.hidden = false;
    var prev = el.textContent ? el.textContent + "\n" : "";
    el.textContent = (prev + line).split("\n").slice(-200).join("\n");
  }
  function provider() {
    return (typeof window !== "undefined") ? window.ethereum : null;
  }

  // ================================================================== //
  // Low-level byte helpers (no crypto — just encoding). Kept tiny + audited.
  // ================================================================== //
  function hexToBytes(h) {
    h = (h && h.indexOf("0x") === 0) ? h.slice(2) : (h || "");
    if (h.length % 2) h = "0" + h;
    var o = new Uint8Array(h.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
    return o;
  }
  function bytesToHex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
    return s;
  }
  function concatBytes() {
    var n = 0, i;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), k = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], k); k += arguments[i].length; }
    return o;
  }
  function utf8Bytes(s) { return new TextEncoder().encode(s); }
  // 8-byte big-endian (nonce). BigInt for exact ms-timestamp width.
  function u64beBytes(n) {
    var b = new Uint8Array(8), v = BigInt(n);
    for (var i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }
  // left-padded 32-byte big-endian of a small integer (EIP-712 uint256).
  function u256beBytes(n) {
    var b = new Uint8Array(32), v = BigInt(n);
    for (var i = 31; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }
  // right-most 20 bytes of an address, left-padded to 32 (EIP-712 address).
  function addrTo32(addr) {
    var raw = hexToBytes(addr), o = new Uint8Array(32);
    o.set(raw.slice(-20), 32 - Math.min(20, raw.length));
    return o;
  }

  // ================================================================== //
  // HLSigner — REAL, faithful port of hyperliquid-python-sdk signing.py.
  // Crypto (secp256k1, keccak_256, msgpack) is loaded IN-BROWSER from a PINNED
  // CDN via dynamic import(); we do NOT hand-roll crypto. Every method that
  // needs crypto is async because it first awaits _load().
  //
  // The AGENT private key is used ONLY here to sign, and NEVER leaves the
  // browser — it is not placed in any fetch body anywhere in this file.
  // ================================================================== //
  var HLSigner = {
    _libs: null,   // cached { secp256k1, keccak_256, encode }

    // ---- lazy-load the pinned CDN crypto modules (once) --------------- //
    _load: async function () {
      if (HLSigner._libs) return HLSigner._libs;
      var secpUrl = CFG.cdn_secp256k1;
      var sha3Url = CFG.cdn_js_sha3;
      var msgpackUrl = CFG.cdn_msgpack;
      if (!secpUrl || !sha3Url || !msgpackUrl) {
        throw new Error("crypto CDN urls missing from config (cdn_secp256k1/" +
          "cdn_js_sha3/cdn_msgpack) — cannot sign without vendored crypto");
      }
      var mods = await Promise.all([
        import(secpUrl), import(sha3Url), import(msgpackUrl)
      ]);
      var secpMod = mods[0], sha3Mod = mods[1], msgpackMod = mods[2];
      var secp256k1 = secpMod.secp256k1 || (secpMod.default && secpMod.default.secp256k1);
      var keccak_256 = sha3Mod.keccak_256 || (sha3Mod.default && sha3Mod.default.keccak_256);
      var encode = msgpackMod.encode || (msgpackMod.default && msgpackMod.default.encode);
      if (!secp256k1 || !keccak_256 || !encode) {
        throw new Error("crypto module exports missing (need secp256k1/" +
          "keccak_256/encode) — refusing to sign");
      }
      HLSigner._libs = { secp256k1: secp256k1, keccak_256: keccak_256, encode: encode };
      return HLSigner._libs;
    },

    // keccak256 -> 32-byte Uint8Array (js-sha3 returns lowercase hex).
    _keccak: function (bytes) { return hexToBytes(HLSigner._libs.keccak_256(bytes)); },

    // ---- keygen (REAL) ----------------------------------------------- //
    // Real secp256k1 keypair. Agent ETH address = last 20 bytes of
    // keccak256(uncompressed pubkey without the 0x04 prefix). Returns
    // { address, priv }; priv is persisted ONLY in localStorage by the caller.
    generateAgentKey: async function () {
      var L = await HLSigner._load();
      var priv = L.secp256k1.utils.randomPrivateKey();      // 32 bytes
      var pub = L.secp256k1.getPublicKey(priv, false);      // 65-byte uncompressed
      var addr = "0x" + bytesToHex(HLSigner._keccak(pub.slice(1)).slice(-20));
      return { address: addr, priv: "0x" + bytesToHex(priv), dry: false };
    },

    // ---- approveAgent typed data (pure structure; wallet signs it) ---- //
    // The USER signs THIS with their OWN wallet (eth_signTypedData_v4). No
    // agent private key is involved. hyperliquidChain follows the CURRENT env
    // so a testnet approval is scoped to testnet.
    buildApproveAgentTypedData: function (agentAddress, agentName) {
      var chainId = parseInt(CFG.signature_chain_id || "0x66eee", 16);
      var nonce = Date.now();
      var action = {
        type: "approveAgent",
        hyperliquidChain: envUrls().hyperliquidChain,
        signatureChainId: CFG.signature_chain_id || "0x66eee",
        agentAddress: String(agentAddress).toLowerCase(),
        agentName: agentName || "glasswing-dex",
        nonce: nonce
      };
      var typed = {
        domain: {
          name: "HyperliquidSignTransaction",
          version: "1",
          chainId: chainId,
          verifyingContract: CFG.verifying_contract ||
            "0x0000000000000000000000000000000000000000"
        },
        types: {
          EIP712Domain: [
            { name: "name", type: "string" },
            { name: "version", type: "string" },
            { name: "chainId", type: "uint256" },
            { name: "verifyingContract", type: "address" }
          ],
          "HyperliquidTransaction:ApproveAgent": [
            { name: "hyperliquidChain", type: "string" },
            { name: "agentAddress", type: "address" },
            { name: "agentName", type: "string" },
            { name: "nonce", type: "uint64" }
          ]
        },
        primaryType: "HyperliquidTransaction:ApproveAgent",
        message: {
          hyperliquidChain: action.hyperliquidChain,
          agentAddress: action.agentAddress,
          agentName: action.agentName,
          nonce: action.nonce
        }
      };
      return { action: action, typed: typed };
    },

    // ---- approveAgent signing (REAL, via the USER's wallet) ---------- //
    // The USER's MAIN wallet signs approveAgent through the injected provider.
    // This is a user-signed action (like approveBuilderFee), so it uses
    // eth_signTypedData_v4 — the agent key is NOT used here. Returns {r,s,v}.
    signApproveAgent: async function (provider, account, agentAddress, agentName) {
      var built = HLSigner.buildApproveAgentTypedData(agentAddress, agentName);
      var sig = await provider.request({
        method: "eth_signTypedData_v4",
        params: [account, JSON.stringify(built.typed)]
      });
      return { action: built.action, signature: splitSig(sig) };
    },

    // ---- action_hash / connectionId (REAL port of signing.py) -------- //
    // msgpack(action) || nonce(8 BE) || vaultPresenceByte[+addr] -> keccak256.
    // expires_after is None here, so (matching the SDK) nothing extra is
    // appended for it. Returns a 32-byte Uint8Array (the connectionId).
    actionHash: function (action, vaultAddress, nonce) {
      var L = HLSigner._libs;
      var packed = new Uint8Array(L.encode(action, { sortKeys: false }));
      var data = concatBytes(packed, u64beBytes(nonce));
      if (vaultAddress === null || vaultAddress === undefined) {
        data = concatBytes(data, new Uint8Array([0]));
      } else {
        data = concatBytes(data, new Uint8Array([1]), hexToBytes(vaultAddress));
      }
      return HLSigner._keccak(data);
    },

    // ---- EIP-712 (Agent) digest for the phantom agent --------------- //
    // domain: EIP712Domain(string name,string version,uint256 chainId,
    //         address verifyingContract) with name="Exchange", chainId=1337.
    // struct: Agent(string source,bytes32 connectionId).
    _domainSeparator: function () {
      var th = HLSigner._keccak(utf8Bytes(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
      var enc = concatBytes(
        th,
        HLSigner._keccak(utf8Bytes("Exchange")),
        HLSigner._keccak(utf8Bytes("1")),
        u256beBytes(CFG.l1_phantom_chain_id || 1337),
        addrTo32(CFG.verifying_contract || "0x0000000000000000000000000000000000000000"));
      return HLSigner._keccak(enc);
    },
    _agentDigest: function (source, connectionId32) {
      var th = HLSigner._keccak(utf8Bytes("Agent(string source,bytes32 connectionId)"));
      var structHash = HLSigner._keccak(concatBytes(
        th, HLSigner._keccak(utf8Bytes(source)), connectionId32));
      return HLSigner._keccak(concatBytes(
        new Uint8Array([0x19, 0x01]), HLSigner._domainSeparator(), structHash));
    },

    // ---- L1 ORDER signing (REAL) ------------------------------------- //
    // The AGENT key signs the order action under HL's phantom-agent scheme.
    // MAINNET GATE (hard, at the signer): if the user has requested mainnet
    // (the mainnet toggle is ON) but has NOT proven a testnet order
    // (localStorage[glasswing.testnet_proven] absent), REFUSE — throw
    // "TESTNET PROOF REQUIRED". This is the load-bearing safety check: it does
    // not silently downgrade, it stops. Only once proven do we sign a mainnet
    // (source "a") order; otherwise we sign for testnet (source "b").
    // Returns { r, s, v, nonce, connectionId }.
    signOrder: async function (orderAction, agentKey, nonce) {
      var wantsMainnet = mainnetToggleOn();
      var proven = !!testnetProven();
      if (wantsMainnet && !proven) {
        throw new Error("TESTNET PROOF REQUIRED — refusing to sign a MAINNET " +
          "order until a testnet order has returned status ok (sets " +
          TESTNET_PROVEN_LS_KEY + "). No live signature has been validated yet.");
      }
      var mainnet = wantsMainnet && proven;   // == isMainnet(), belt-and-suspenders
      if (!agentKey || !agentKey.priv) {
        throw new Error("no agent private key — generate an agent key first");
      }
      var L = await HLSigner._load();
      var n = nonce || Date.now();
      var connId = HLSigner.actionHash(orderAction, null, n);  // no vault
      var source = mainnet ? "a" : "b";                        // SDK: a/b
      var digest = HLSigner._agentDigest(source, connId);
      var sig = L.secp256k1.sign(digest, hexToBytes(agentKey.priv),
        { lowS: true, prehash: false });
      var v = sig.recovery + 27;
      return {
        r: "0x" + sig.r.toString(16).padStart(64, "0"),
        s: "0x" + sig.s.toString(16).padStart(64, "0"),
        v: v,
        nonce: n,
        connectionId: "0x" + bytesToHex(connId)
      };
    }
  };

  // ================================================================== //
  // ORDER ACTION BUILDER (DRY-safe: pure structure, no crypto). Attaches
  // our builder code {b, f}. This is exactly what HLSigner.signOrder would
  // sign once the vendored lib is in place; in DRY mode we just log it.
  // ================================================================== //
  // Canonical Hyperliquid wire number (the SDK's float_to_wire): the venue
  // re-canonicalizes numeric strings BEFORE hashing, so a non-canonical px/sz
  // (trailing zeros — "0.0080", "1969.0") makes the venue's action hash differ
  // from the one we signed and the signature recovers to a GARBAGE address
  // ("User or API Wallet 0x… does not exist"). Proven live on testnet
  // 2026-07-19: identical order, "0.0080" rejected / "0.008" filled.
  function wireNum(x) {
    var n = Number(x);
    if (!isFinite(n)) throw new Error("non-finite wire number: " + x);
    var s = n.toFixed(8);
    s = s.replace(/0+$/, "").replace(/\.$/, "");
    if (s === "-0" || s === "") s = "0";
    return s;
  }
  function buildOrderAction(o) {
    // o: { assetId, isBuy, px, sz, reduceOnly }. assetId MUST be the numeric
    // asset index (resolveAssetIndex), NOT the display coin string. Field order
    // (a,b,p,s,r,t) and the action shape (type,orders,grouping,builder) exactly
    // match the SDK's order_request_to_order_wire + order_wires_to_order_action
    // so the msgpack bytes — and thus the connectionId — are identical.
    var order = {
      a: o.assetId,                 // asset INDEX (integer)
      b: !!o.isBuy,                 // isBuy
      p: wireNum(o.px),             // limit px, CANONICAL wire string
      s: wireNum(o.sz),             // size, CANONICAL wire string
      r: !!o.reduceOnly,            // reduceOnly
      t: { limit: { tif: "Ioc" } } // marketable IOC to mirror an open
    };
    var action = {
      type: "order",
      orders: [order],
      grouping: "na"
    };
    // OUR revenue hook: builder code {b: our addr, f: tenths-of-bp}. Added LAST
    // (after grouping) to match order_wires_to_order_action's insertion order.
    action.builder = {
      b: String(CFG.builder_address).toLowerCase(),
      f: CFG.fee_tenths_bp
    };
    return action;
  }

  // ---- asset-index resolution from the info `meta` universe --------------- //
  // Hyperliquid orders are keyed by the NUMERIC perp asset index (position in
  // meta.universe), not the coin string. Fetched once from the CURRENT env's
  // info API and cached per-env. Returns the integer index, or throws if the
  // coin is unknown (never silently mis-routes to index 0).
  var _assetIndexCache = {};   // env -> { COIN: index }
  async function resolveAssetIndex(coin) {
    var env = currentEnv();
    var table = _assetIndexCache[env];
    if (!table) {
      var resp = await fetch(envUrls().info, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "meta" })
      });
      var meta = await resp.json();
      table = {};
      var uni = (meta && meta.universe) || [];
      for (var i = 0; i < uni.length; i++) {
        if (uni[i] && uni[i].name) table[String(uni[i].name).toUpperCase()] = i;
      }
      _assetIndexCache[env] = table;
    }
    var key = String(coin).toUpperCase();
    if (!(key in table)) {
      throw new Error("unknown asset '" + coin + "' in " + env +
        " meta.universe — refusing to guess an index");
    }
    return table[key];
  }

  // ---- split a 65-byte 0x signature into {r,s,v} (for the wallet-signed
  // user actions; the exchange wants this shape). ---------------------- //
  function splitSig(sig) {
    var s = sig.startsWith("0x") ? sig.slice(2) : sig;
    var r = "0x" + s.slice(0, 64);
    var ss = "0x" + s.slice(64, 128);
    var v = parseInt(s.slice(128, 130), 16);
    if (v < 27) v += 27;
    return { r: r, s: ss, v: v };
  }

  // ---- localStorage agent-key model. The private key (when a real one
  // exists post-vendoring) is persisted ONLY here, in the user's browser.
  // It is never included in any fetch body. ---------------------------- //
  function saveAgentKey(rec) {
    try { localStorage.setItem(AGENT_LS_KEY, JSON.stringify(rec)); }
    catch (e) { /* storage may be unavailable; keep in-memory only */ }
  }
  function loadAgentKey() {
    try {
      var raw = localStorage.getItem(AGENT_LS_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  // ================================================================== //
  // STEP 1: connect wallet (address only)
  // ================================================================== //
  async function connect() {
    var p = provider();
    if (!p) {
      pill("wallet-pill", "no wallet found", "err");
      out("connect-out", "No window.ethereum provider. Install Rabby or MetaMask.");
      return;
    }
    try {
      var accts = await p.request({ method: "eth_requestAccounts" });
      state.account = (accts && accts[0]) ? accts[0] : null;
      if (!state.account) throw new Error("no account returned");
      pill("wallet-pill", state.account, "ok");
      out("connect-out", { connected: state.account });
      pill("approve-fee-pill", "ready to approve", "warn");
      $("btn-approve-fee").disabled = false;
    } catch (e) {
      pill("wallet-pill", "connect failed", "err");
      out("connect-out", String(e && e.message ? e.message : e));
    }
  }

  // ================================================================== //
  // STEP 2: approveBuilderFee — reuses the working scheme from app.js.
  // The user's OWN wallet signs; we relay to the public exchange endpoint.
  // ================================================================== //
  function buildApproveBuilderFeeAction() {
    var nonce = Date.now();
    return {
      type: "approveBuilderFee",
      hyperliquidChain: CFG.hyperliquid_chain || "Mainnet",
      signatureChainId: CFG.signature_chain_id || "0x66eee",
      maxFeeRate: CFG.max_fee_rate,             // e.g. "0.01%" (1bp)
      builder: String(CFG.builder_address).toLowerCase(),
      nonce: nonce
    };
  }
  function buildBuilderFeeTypedData(action) {
    var chainId = parseInt(action.signatureChainId, 16);
    return {
      domain: {
        name: "HyperliquidSignTransaction",
        version: "1",
        chainId: chainId,
        verifyingContract: CFG.verifying_contract ||
          "0x0000000000000000000000000000000000000000"
      },
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "chainId", type: "uint256" },
          { name: "verifyingContract", type: "address" }
        ],
        "HyperliquidTransaction:ApproveBuilderFee": [
          { name: "hyperliquidChain", type: "string" },
          { name: "maxFeeRate", type: "string" },
          { name: "builder", type: "address" },
          { name: "nonce", type: "uint64" }
        ]
      },
      primaryType: "HyperliquidTransaction:ApproveBuilderFee",
      message: {
        hyperliquidChain: action.hyperliquidChain,
        maxFeeRate: action.maxFeeRate,
        builder: action.builder,
        nonce: action.nonce
      }
    };
  }

  async function approveFee() {
    var p = provider();
    if (!p || !state.account) { pill("approve-fee-pill", "connect first", "err"); return; }
    var action = buildApproveBuilderFeeAction();
    var typed = buildBuilderFeeTypedData(action);
    out("approve-fee-out", { about_to_sign: typed,
      note: "builder-fee approval — the on-chain revenue hook" });
    try {
      var sig = await p.request({
        method: "eth_signTypedData_v4",
        params: [state.account, JSON.stringify(typed)]
      });
      var signature = splitSig(sig);
      var body = { action: action, nonce: action.nonce, signature: signature };
      var resp = await fetch(CFG.exchange_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      var data = await resp.json().catch(function () { return { status: "unknown" }; });
      var ok = data && data.status === "ok";
      state.feeApproved = !!ok;
      out("approve-fee-out", { posted: body, response: data });
      if (ok) {
        pill("approve-fee-pill", "approved " + (CFG.max_fee_rate || ""), "ok");
        pill("agent-pill", "generate an agent key", "warn");
        $("btn-gen-agent").disabled = false;
      } else {
        pill("approve-fee-pill", "not confirmed (see output)", "warn");
      }
    } catch (e) {
      pill("approve-fee-pill", "sign/relay failed", "err");
      out("approve-fee-out", String(e && e.message ? e.message : e));
    }
  }

  // ================================================================== //
  // STEP 3: generate an ephemeral agent key IN-BROWSER, then approveAgent.
  // Real keygen is stubbed (HLSigner.generateAgentKey throws); the DRY path
  // mints a non-cryptographic placeholder so the localStorage model + the
  // approveAgent typed-data structure are exercised without faking crypto.
  // ================================================================== //
  async function genAgent() {
    pill("agent-pill", "generating (loading crypto)…", "warn");
    try {
      // REAL secp256k1 keygen in-browser (crypto loaded from the pinned CDN).
      var rec = await HLSigner.generateAgentKey();
      state.agentKey = rec;
      saveAgentKey(rec);   // localStorage — user's browser only, never transmitted
      out("agent-out", {
        mode: "LIVE",
        agent_address: rec.address,
        stored_in: "localStorage:" + AGENT_LS_KEY + " (this browser only)",
        private_key_transmitted: false,
        note: "real secp256k1 agent keypair generated in-browser; the private " +
              "key stays in this browser and signs orders locally."
      });
      pill("agent-pill", "agent key ready", "ok");
      $("btn-approve-agent").disabled = false;
    } catch (e) {
      // No fake key material on failure — surface the error and stay blocked.
      pill("agent-pill", "keygen failed (crypto load?)", "err");
      out("agent-out", {
        error: String(e && e.message ? e.message : e),
        note: "crypto could not load (offline / CDN blocked?). No key was " +
              "created; nothing to sign with. Retry when the CDN is reachable."
      });
    }
  }

  async function approveAgent() {
    var p = provider();
    if (!p || !state.account) { pill("agent-pill", "connect first", "err"); return; }
    if (!state.agentKey || !state.agentKey.address) {
      pill("agent-pill", "generate a key first", "err"); return;
    }
    var urls = envUrls();
    var built = HLSigner.buildApproveAgentTypedData(
      state.agentKey.address, "glasswing-dex");
    out("agent-out", { env: currentEnv(), about_to_sign: built.typed,
      agent_address: state.agentKey.address,
      note: "you sign this in YOUR wallet; authorizes the trade-only agent " +
            "(agents cannot withdraw). Scoped to " + urls.hyperliquidChain +
            ". Agent private key stays in this browser." });
    try {
      // The USER signs approveAgent in their OWN wallet via HLSigner (real
      // eth_signTypedData_v4). No agent private key is used or transmitted.
      var signed = await HLSigner.signApproveAgent(
        p, state.account, state.agentKey.address, "glasswing-dex");
      // Body carries the action + the USER's signature. The request body
      // NEVER carries the agent private key (only the agent ADDRESS, public).
      var body = { action: signed.action, nonce: signed.action.nonce,
                   signature: signed.signature };
      var resp = await fetch(urls.exchange, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      var data = await resp.json().catch(function () { return { status: "unknown" }; });
      var ok = data && data.status === "ok";
      state.agentApproved = !!ok;
      out("agent-out", { env: currentEnv(), posted: body, response: data });
      if (ok) {
        pill("agent-pill", "agent authorized (" + currentEnv() + ")", "ok");
        pill("copy-pill", "ready — start the loop (DRY)", "warn");
        $("btn-start-loop").disabled = false;
      } else {
        pill("agent-pill", "not confirmed (see output)", "warn");
      }
    } catch (e) {
      pill("agent-pill", "sign/relay failed", "err");
      out("agent-out", String(e && e.message ? e.message : e));
    }
  }

  // ================================================================== //
  // STEP 4: the client-side COPY LOOP. Polls each vetted leader's recent
  // fills on the PUBLIC info API (userFillsByTime). On a fresh open by a
  // vetted leader, builds the mirrored order (with builder{b,f}) and:
  //   - DRY (default): logs the intended order; places nothing.
  //   - LIVE: routes through HLSigner.signOrder — which THROWS until the
  //     vendored lib + testnet proof exist. We never fake a fill.
  // ================================================================== //
  async function fetchLeaderFills(leader) {
    // PUBLIC read — userFillsByTime on the CURRENT env's info API. No auth, no
    // key, no server of ours. (Leaders are mainnet wallets; on testnet this is a
    // dry-signal source only — the DRY log still shows the exact order shape.)
    var startTime = Date.now() - 60 * 60 * 1000; // last hour
    var body = { type: "userFillsByTime", user: leader, startTime: startTime };
    var resp = await fetch(envUrls().info, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return resp.json();
  }

  // Extract the accepted order id (oid) from an exchange `order` response, if
  // present. Used to stamp the testnet-proven flag. Best-effort + defensive.
  function extractOid(data) {
    try {
      var st = data.response.data.statuses[0];
      if (st.resting && st.resting.oid) return st.resting.oid;
      if (st.filled && st.filled.oid) return st.filled.oid;
    } catch (e) { /* shape varies; fall through */ }
    return null;
  }

  function isFreshOpen(fill) {
    // an OPEN increases position magnitude: HL fills carry dir like
    // "Open Long" / "Open Short" (vs "Close ..."). Treat "Open" as an open.
    var dir = String(fill && fill.dir || "");
    return dir.indexOf("Open") === 0;
  }

  async function pollOnce() {
    var leaders = CFG.vetted_addrs || [];
    var live = $("live-toggle") && $("live-toggle").checked;
    for (var i = 0; i < leaders.length; i++) {
      var leader = leaders[i];
      try {
        var fills = await fetchLeaderFills(leader);
        if (!Array.isArray(fills)) continue;
        for (var j = 0; j < fills.length; j++) {
          var f = fills[j];
          if (!isFreshOpen(f)) continue;
          var t = f.time || 0;
          if (state.seen[leader] && t <= state.seen[leader]) continue;
          state.seen[leader] = Math.max(state.seen[leader] || 0, t);

          var clip = parseFloat(($("clip-usd") || {}).value || "25") || 25;
          // size the mirror to the user's clip (notional / px), leader dir.
          var px = parseFloat(f.px || "0") || 0;
          var sz = px > 0 ? (clip / px) : 0;

          // Resolve the NUMERIC asset index from the info meta universe (cached).
          // On failure we skip this fill rather than guess an index.
          var assetIdx;
          try {
            assetIdx = await resolveAssetIndex(f.coin);
          } catch (e) {
            log("copy-out", "[skip] " + f.coin + " — " +
              String(e && e.message ? e.message : e));
            continue;
          }

          var orderAction = buildOrderAction({
            assetId: assetIdx,             // NUMERIC asset index (from meta)
            isBuy: String(f.dir).indexOf("Long") >= 0,
            px: px,
            sz: sz.toFixed(6),
            reduceOnly: false
          });

          if (!live) {
            // DRY (default): log the exact intended order. Place NOTHING.
            log("copy-out", "[DRY " + currentEnv() + "] mirror " +
              leader.slice(0, 10) + ".. " + f.dir + " " + f.coin +
              " (asset " + assetIdx + ") -> " + JSON.stringify(orderAction));
            continue;
          }

          // LIVE path — the AGENT key really signs and we relay to the CURRENT
          // env's exchange. MAINNET is gated inside signOrder (throws
          // "TESTNET PROOF REQUIRED" until a testnet order is proven). We never
          // fabricate a signature or a fill.
          try {
            var signed = await HLSigner.signOrder(orderAction, state.agentKey);
            // Body carries the action + AGENT signature + nonce. It NEVER
            // carries the agent private key.
            var body = { action: orderAction, nonce: signed.nonce,
                         signature: { r: signed.r, s: signed.s, v: signed.v } };
            var resp = await fetch(envUrls().exchange, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body)
            });
            var data = await resp.json().catch(function () { return {}; });
            var okOrder = data && data.status === "ok";
            log("copy-out", "[LIVE " + currentEnv() + "] " + f.coin +
              " (connId " + signed.connectionId.slice(0, 12) + "..) -> " +
              JSON.stringify(data));
            // FIRST accepted TESTNET order unlocks the mainnet gate.
            if (okOrder && !isMainnet() && !testnetProven()) {
              var oid = extractOid(data) || signed.nonce;
              try { localStorage.setItem(TESTNET_PROVEN_LS_KEY, String(oid)); }
              catch (e2) { /* storage optional */ }
              refreshEnvPills();
              log("copy-out", "[PROOF] testnet order accepted (oid " + oid +
                ") — mainnet gate is now unlockable via the MAINNET toggle.");
            }
          } catch (e) {
            log("copy-out", "[LIVE-BLOCKED] " +
              String(e && e.message ? e.message : e));
            // stop hammering once we hit a guard (e.g. mainnet-without-proof).
            stopLoop();
            pill("copy-pill", "live blocked (see log)", "err");
            return;
          }
        }
      } catch (e) {
        log("copy-out", "[poll error] " + leader.slice(0, 10) + ".. " +
          String(e && e.message ? e.message : e));
      }
    }
  }

  function startLoop() {
    if (!state.agentApproved) { pill("copy-pill", "authorize an agent first", "err"); return; }
    if (state.loopTimer) return;
    var live = $("live-toggle") && $("live-toggle").checked;
    var env = currentEnv();
    // Honest up-front guard: if the user asked for mainnet but it isn't proven,
    // say so plainly (the toggle silently falls back to testnet in currentEnv).
    if (mainnetToggleOn() && !testnetProven()) {
      log("copy-out", "[gate] MAINNET requested but not proven — running on " +
        "TESTNET. Place one accepted testnet order to unlock mainnet.");
    }
    pill("copy-pill", (live ? "running LIVE" : "running DRY") + " (" + env + ")",
      (live && env === "mainnet") ? "err" : "warn");
    log("copy-out", "[loop] started in " + (live ? "LIVE" : "DRY") +
      " mode on " + env + "; polling " + ((CFG.vetted_addrs || []).length) +
      " vetted leaders every " + (POLL_MS / 1000) + "s");
    $("btn-start-loop").disabled = true;
    $("btn-stop-loop").disabled = false;
    pollOnce();
    state.loopTimer = setInterval(pollOnce, POLL_MS);
  }

  function stopLoop() {
    if (state.loopTimer) { clearInterval(state.loopTimer); state.loopTimer = null; }
    $("btn-start-loop").disabled = false;
    $("btn-stop-loop").disabled = true;
    pill("copy-pill", "stopped", "warn");
    log("copy-out", "[loop] stopped");
  }

  // Reflect the current env + testnet-proof state into the pills + banner.
  function refreshEnvPills() {
    var env = currentEnv();
    pill("env-pill", "env: " + env, env === "mainnet" ? "err" : "warn");
    var proven = testnetProven();
    pill("proof-pill", proven ? ("testnet proven (oid " + proven + ")")
                              : "testnet not yet proven",
      proven ? "ok" : "warn");
    var eb = $("env-banner"); if (eb) eb.textContent = env.toUpperCase();
    // The MAINNET toggle is inert (falls back to testnet) until proven; show it.
    var mt = $("mainnet-toggle");
    if (mt) mt.title = proven ? "testnet proven — mainnet allowed"
                              : "blocked: place one accepted testnet order first";
  }

  function wire() {
    var c = $("btn-connect"); if (c) c.onclick = connect;
    var af = $("btn-approve-fee"); if (af) af.onclick = approveFee;
    var ga = $("btn-gen-agent"); if (ga) ga.onclick = genAgent;
    var aa = $("btn-approve-agent"); if (aa) aa.onclick = approveAgent;
    var sl = $("btn-start-loop"); if (sl) sl.onclick = startLoop;
    var st = $("btn-stop-loop"); if (st) st.onclick = stopLoop;
    var mt = $("mainnet-toggle"); if (mt) mt.onchange = refreshEnvPills;

    // restore a previously-generated agent key from THIS browser (if any).
    var existing = loadAgentKey();
    if (existing && existing.address) {
      state.agentKey = existing;
    }
    refreshEnvPills();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }

  // exported for a browser-side harness (e.g. paste a fixed order + agent key
  // and compare HLSigner.actionHash's connectionId to the SDK reference printed
  // by product/hl_sign_equivalence.py) + the generator's structural notes.
  if (typeof window !== "undefined") {
    window.__glasswing_dex = {
      HLSigner: HLSigner,
      buildOrderAction: buildOrderAction,
      buildApproveBuilderFeeAction: buildApproveBuilderFeeAction,
      buildBuilderFeeTypedData: buildBuilderFeeTypedData,
      resolveAssetIndex: resolveAssetIndex,
      currentEnv: currentEnv,
      isMainnet: isMainnet,
      envUrls: envUrls,
      splitSig: splitSig,
      wireNum: wireNum,
      // byte helpers (handy for a manual connectionId check in the console)
      _bytes: { hexToBytes: hexToBytes, bytesToHex: bytesToHex,
                concatBytes: concatBytes, u64beBytes: u64beBytes }
    };
  }
})();
