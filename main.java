/*
 * Transacto — OTC trading client for the Otc (EVM) contract.
 * Supports listing orders, posting, filling, and cancelling. Crypto and RWA asset types.
 * Single-file app; run with: java Transacto.java (or compile then java Transacto).
 */

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

public final class Transacto {

    private static final int STATUS_OPEN = 0;
    private static final int STATUS_FILLED = 1;
    private static final int STATUS_CANCELLED = 2;
    private static final String STATUS_OPEN_STR = "OPEN";
    private static final String STATUS_FILLED_STR = "FILLED";
    private static final String STATUS_CANCELLED_STR = "CANCELLED";
    private static final int MAX_RPC_RETRIES = 3;
    private static final long RPC_RETRY_DELAY_MS = 500;
    private static final String CONFIG_FILENAME = "transacto.conf";
    private static final Pattern ADDRESS_PATTERN = Pattern.compile("^0x[0-9a-fA-F]{40}$");
    private static final Pattern ORDER_ID_PATTERN = Pattern.compile("^0x[0-9a-fA-F]{64}$");

    // -------------------------------------------------------------------------
    // CONTRACT & ROLES (must match Otc.sol deployment)
    // -------------------------------------------------------------------------

    private static final String DEFAULT_RPC = "https://eth.llamarpc.com";
    private static final String OTC_CONTRACT_ADDRESS = "0x7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6";
    private static final String OTC_OPERATOR = "0x1a2b3c4d5e6f7890a1b2c3d4e5f67890a1b2c3d4e5";
    private static final String OTC_TREASURY = "0x2b3c4d5e6f7890a1b2c3d4e5f67890a1b2c3d4e5f6";
    private static final String OTC_ESCROW_KEEPER = "0x3c4d5e6f7890a1b2c3d4e5f67890a1b2c3d4e5f678";
    private static final String OTC_NAMESPACE_HEX = "4d5e6f7890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e";

    private static final BigInteger OTC_ASSET_CRYPTO = BigInteger.ZERO;
    private static final BigInteger OTC_ASSET_RWA = BigInteger.ONE;
    private static final BigInteger OTC_VIEW_BATCH = new BigInteger("48");
    private static final BigInteger OTC_BPS_DENOM = new BigInteger("10000");
    private static final BigInteger PRICE_DECIMALS = new BigInteger("1000000000000000000"); // 1e18

    // Selectors (first 4 bytes of keccak256 of signature)
    private static final String POST_ORDER_SELECTOR = "0x8a4c5f2e";
    private static final String FILL_ORDER_SELECTOR = "0x3d7e849a";
    private static final String CANCEL_ORDER_SELECTOR = "0xb8c7e9d1";
    private static final String GET_ORDER_VIEW_SELECTOR = "0x7f2a1b4c";
    private static final String GET_ORDER_SUMMARIES_BATCH_SELECTOR = "0x9e3f2a1d";
    private static final String GET_ORDER_IDS_LENGTH_SELECTOR = "0x1a2b3c4e";
    private static final String GET_ORDER_AT_SELECTOR = "0x5d6e7f8a";
    private static final String GET_ORDER_VIEW_BY_INDEX_SELECTOR = "0x2b4c6e8f";
    private static final String GET_PLATFORM_STATS_SELECTOR = "0x4e5f6a7b";
    private static final String IS_PLATFORM_PAUSED_SELECTOR = "0x8c9d0e1f";
    private static final String MIN_ORDER_SIZE_SELECTOR = "0x1f2a3b4c";
    private static final String FEE_PERCENT_BPS_SELECTOR = "0x5d6e7f90";
    private static final String GET_ORDER_IDS_SELECTOR = "0x9a0b1c2d";

    // -------------------------------------------------------------------------
    // STATE
    // -------------------------------------------------------------------------

    private String rpcUrl = DEFAULT_RPC;
    private String privateKeyHex; // optional; for sending txs
    private final OtcRpc rpc;

    public Transacto() {
        this.rpc = new OtcRpc(OTC_CONTRACT_ADDRESS);
    }

    public void setRpcUrl(String url) { this.rpcUrl = url != null ? url : DEFAULT_RPC; }
    public String getRpcUrl() { return rpcUrl; }
    public void setPrivateKeyHex(String hex) { this.privateKeyHex = hex; }
    public boolean hasPrivateKey() { return privateKeyHex != null && !privateKeyHex.isBlank(); }

    // -------------------------------------------------------------------------
    // DATA MODELS
    // -------------------------------------------------------------------------

    public static final class OrderView {
        public String orderId;
        public String maker;
        public int assetType;
        public String assetId;
        public BigInteger amount;
        public BigInteger pricePerUnit;
        public boolean isSell;
        public BigInteger filledAmount;
        public int status;
        public BigInteger createdAt;

        @Override
        public String toString() {
            return String.format("OrderView{id=%s maker=%s assetType=%d amount=%s price=%s isSell=%s filled=%s status=%d}",
                orderId, maker, assetType, amount, pricePerUnit, isSell, filledAmount, status);
        }
    }

    public static final class OrderSummary {
        public String orderId;
        public String maker;
        public BigInteger amount;
        public BigInteger filledAmount;
        public BigInteger pricePerUnit;
        public boolean isSell;
        public int status;
    }

    public static final class PlatformStats {
        public BigInteger totalOrders;
        public BigInteger openOrders;
        public BigInteger minOrderWei;
        public BigInteger feeBps;
        public boolean paused;
    }

    // -------------------------------------------------------------------------
    // ABI ENCODING HELPERS
    // -------------------------------------------------------------------------

    private static String padLeft(String hex, int bytesLen) {
        int len = bytesLen * 2;
        if (hex == null) hex = "0";
        hex = hex.replaceFirst("^0x", "");
        if (hex.length() >= len) return hex.substring(hex.length() - len);
        return "0".repeat(len - hex.length()) + hex;
    }

    private static String padAddress(String addr) {
        if (addr == null) return padLeft("0", 20);
        addr = addr.replaceFirst("^0x", "");
        return padLeft(addr, 20);
    }

    private static String padBytes32(String h) {
        if (h == null) h = "0";
        h = h.replaceFirst("^0x", "");
        return padLeft(h, 32);
    }

    private static String padUint256(BigInteger n) {
        if (n == null) n = BigInteger.ZERO;
        String hex = n.toString(16);
        return padLeft(hex, 32);
    }

    private static String encodeBool(boolean b) {
        return padLeft(b ? "1" : "0", 32);
    }

    // -------------------------------------------------------------------------
    // RPC CALL (eth_call)
    // -------------------------------------------------------------------------

    private String ethCall(String to, String data) throws IOException {
        String body = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"" + to + "\",\"data\":\"" + data + "\"},\"latest\"],\"id\":1}";
        return postJson(rpcUrl, body);
    }

    private String postJson(String urlString, String jsonBody) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        if (code != 200) {
            try (InputStream err = conn.getErrorStream()) {
                String errBody = err != null ? new String(err.readAllBytes(), StandardCharsets.UTF_8) : "";
                throw new IOException("HTTP " + code + " " + errBody);
            }
        }
        try (InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String extractResult(String jsonResponse) {
        if (jsonResponse == null) return null;
        int i = jsonResponse.indexOf("\"result\":\"");
        if (i < 0) return null;
        i += 10;
        int j = jsonResponse.indexOf("\"", i);
        if (j < 0) return null;
        return jsonResponse.substring(i, j);
    }

    // -------------------------------------------------------------------------
    // CONTRACT VIEW CALLS (decode from 0x-prefixed hex)
    // -------------------------------------------------------------------------

    public BigInteger getOrderIdsLength() throws IOException {
        String data = GET_ORDER_IDS_LENGTH_SELECTOR;
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        if (result == null || result.length() < 66) return BigInteger.ZERO;
        return new BigInteger(result.substring(2), 16);
    }

    public String getOrderAt(BigInteger index) throws IOException {
        String data = GET_ORDER_AT_SELECTOR + padUint256(index);
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        if (result == null || result.length() < 66) return null;
        return "0x" + result.substring(2).toLowerCase();
    }

    public OrderView getOrderViewByIndex(BigInteger index) throws IOException {
        String data = GET_ORDER_VIEW_BY_INDEX_SELECTOR + padUint256(index);
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        return decodeOrderView(result);
    }

    public OrderView getOrderView(String orderIdHex) throws IOException {
        String data = GET_ORDER_VIEW_SELECTOR + padBytes32(orderIdHex);
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        return decodeOrderView(result);
    }

    private OrderView decodeOrderView(String hex) {
        if (hex == null || hex.length() < 2) return null;
        hex = hex.replaceFirst("^0x", "");
        int offset = 0;
        if (hex.length() < 64 * 10) return null;
        OrderView v = new OrderView();
        v.orderId = "0x" + hex.substring(offset, offset + 64).replaceFirst("^0+", "");
        if (v.orderId.length() < 66) v.orderId = "0x" + hex.substring(offset, offset + 64);
        offset += 64;
        v.maker = "0x" + hex.substring(offset + 24, offset + 64);
        offset += 64;
        v.assetType = new BigInteger(hex.substring(offset, offset + 64), 16).intValue();
        offset += 64;
        v.assetId = "0x" + hex.substring(offset, offset + 64);
        offset += 64;
        v.amount = new BigInteger(hex.substring(offset, offset + 64), 16);
        offset += 64;
        v.pricePerUnit = new BigInteger(hex.substring(offset, offset + 64), 16);
        offset += 64;
        v.isSell = new BigInteger(hex.substring(offset, offset + 64), 16).signum() != 0;
        offset += 64;
        v.filledAmount = new BigInteger(hex.substring(offset, offset + 64), 16);
        offset += 64;
        v.status = new BigInteger(hex.substring(offset, offset + 64), 16).intValue();
        offset += 64;
        v.createdAt = new BigInteger(hex.substring(offset, offset + 64), 16);
        return v;
    }

    public List<OrderView> getOrderViewsBatch(int offset, int limit) throws IOException {
        BigInteger len = getOrderIdsLength();
        if (len.compareTo(BigInteger.valueOf(offset)) <= 0) return Collections.emptyList();
        int end = Math.min(offset + limit, len.intValue());
        int batch = Math.min(limit, 48);
        List<OrderView> list = new ArrayList<>();
        for (int i = offset; i < end && (i - offset) < batch; i++) {
            OrderView v = getOrderViewByIndex(BigInteger.valueOf(i));
            if (v != null) list.add(v);
        }
        return list;
    }

    public boolean isPlatformPaused() throws IOException {
        String data = IS_PLATFORM_PAUSED_SELECTOR;
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        if (result == null || result.length() < 66) return true;
        return new BigInteger(result.substring(2), 16).signum() != 0;
    }

    public BigInteger getMinOrderWei() throws IOException {
        String data = MIN_ORDER_SIZE_SELECTOR;
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        if (result == null || result.length() < 66) return BigInteger.ZERO;
        return new BigInteger(result.substring(2), 16);
    }

    public BigInteger getFeeBps() throws IOException {
        String data = FEE_PERCENT_BPS_SELECTOR;
        String raw = ethCall(OTC_CONTRACT_ADDRESS, data);
        String result = extractResult(raw);
        if (result == null || result.length() < 66) return BigInteger.ZERO;
        return new BigInteger(result.substring(2), 16);
    }

    public PlatformStats getPlatformStats() throws IOException {
        PlatformStats s = new PlatformStats();
        s.totalOrders = getOrderIdsLength();
        s.paused = isPlatformPaused();
        s.minOrderWei = getMinOrderWei();
        s.feeBps = getFeeBps();
        int open = 0;
        for (BigInteger i = BigInteger.ZERO; i.compareTo(s.totalOrders) < 0; i = i.add(BigInteger.ONE)) {
            OrderView v = getOrderViewByIndex(i);
            if (v != null && v.status == 0) open++;
        }
        s.openOrders = BigInteger.valueOf(open);
        return s;
    }

    public BigInteger getFillValueWei(String orderIdHex, BigInteger fillAmount) {
        OrderView v = null;
        try { v = getOrderView(orderIdHex); } catch (IOException e) { return null; }
        if (v == null) return null;
        return v.pricePerUnit.multiply(fillAmount).divide(PRICE_DECIMALS);
    }

    // -------------------------------------------------------------------------
    // BUILD TRANSACTION DATA (for future eth_sendRawTransaction)
    // -------------------------------------------------------------------------

    public String buildPostOrderData(BigInteger assetType, String assetIdHex, BigInteger amount, BigInteger pricePerUnit, boolean isSell) {
        return POST_ORDER_SELECTOR
            + padUint256(assetType)
            + padBytes32(assetIdHex)
            + padUint256(amount)
            + padUint256(pricePerUnit)
            + encodeBool(isSell);
    }

    public String buildFillOrderData(String orderIdHex, BigInteger fillAmount) {
        return FILL_ORDER_SELECTOR + padBytes32(orderIdHex) + padUint256(fillAmount);
    }
