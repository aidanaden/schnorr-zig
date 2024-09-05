const std = @import("std");
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512_256;
const CompressedScalar = Ristretto255.scalar.CompressedScalar;

const schnorr = @import("schnorr.zig");
const KeyPair = schnorr.KeyPair;

fn generate_nonces(comptime num_nonces: u32) ![num_nonces]KeyPair {
    var nonces: [num_nonces]KeyPair = undefined;
    for (0..num_nonces) |i| {
        const nonce = try schnorr.generate_nonce();
        nonces[i] = nonce;
    }
    return nonces;
}

/// Computes L by hashing the concatenation of all public key bytes.
///
/// Inputs:
/// - `public_keys`: an array of public keys
///
/// Returns:
/// - L value as a `Scalar`
fn compute_pubkeys_hash(pubkeys: std.ArrayList(Ristretto255), allocator: Allocator) ![32]u8 {
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();
    for (pubkeys.items) |pub_key| {
        try concatenated.appendSlice(&pub_key.toBytes());
    }
    const concatenated_slice = try concatenated.toOwnedSlice();

    var out: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(concatenated_slice, &out, .{});
    allocator.free(concatenated_slice);
    return out;
}

/// Computes a_i for signer_i via H(L || X_i)
///
/// Inputs:
/// - `pubkeys_hash`: hash of all signers public keys
///
/// Returns:
/// - a_i value as a `Scalar`
fn compute_signer_hash(pubkeys_hash: [32]u8, signer_pubkey: *const Ristretto255, allocator: Allocator) ![32]u8 {
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();
    try concatenated.appendSlice(&pubkeys_hash);
    try concatenated.appendSlice(&signer_pubkey.toBytes());
    const concatenated_slice = try concatenated.toOwnedSlice();

    var out: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(concatenated_slice, &out, .{});
    allocator.free(concatenated_slice);
    return out;
}

const AggregatedPubkey = struct { point: Ristretto255, hash: [32]u8 };

/// Computes the aggregate public key X via sum of all a_i * X_i
///
/// Inputs:
/// - `pubkeys`: an array of public keys as Ristretto255 points
///
/// Returns:
/// - aggregate public key X as a Ristretto255 point
fn compute_aggregate_pubkey(pubkeys: std.ArrayList(Ristretto255), allocator: Allocator) !AggregatedPubkey {
    std.debug.assert(pubkeys.items.len > 0);

    var aggregated_pubkey: ?Ristretto255 = null;
    const L = try compute_pubkeys_hash(pubkeys, allocator);
    for (pubkeys.items) |pub_key| {
        const a_i = try compute_signer_hash(L, &pub_key, allocator);
        const point: Ristretto255 = try pub_key.mul(a_i);
        if (aggregated_pubkey == null) {
            aggregated_pubkey = point;
            continue;
        }
        aggregated_pubkey.? = aggregated_pubkey.?.add(point);
    }
    return AggregatedPubkey{
        .point = aggregated_pubkey.?,
        .hash = L,
    };
}

fn compute_group_nonces(signers_nonces: std.ArrayList([2]Ristretto255)) [2]Ristretto255 {
    std.debug.assert(signers_nonces.items.len > 0);

    var group_nonces: [2]Ristretto255 = undefined;
    for (signers_nonces.items, 0..) |signer_nonces, i| {
        if (i == 0) {
            group_nonces = signer_nonces;
            continue;
        }
        for (0..2) |j| {
            group_nonces[j] = group_nonces[j].add(signer_nonces[j]);
        }
    }
    return group_nonces;
}

/// Computes b for signer_i via H(X || R_1 || R_2 || m)
///
/// Inputs:
/// - `aggregated_pubkey`: Aggregated public key as a `Ristretto255` point
/// - `group_nonces`: Array of summed nonces (default to 2)
/// - `message`: Message to sign
/// - `allocator`: Allocator to allocate arraylist of bytes to be hashed
///
/// Returns:
/// - b value as a `Scalar`
fn compute_nonce_coeff(aggregated_pubkey: *const Ristretto255, group_nonces: *const [2]Ristretto255, message: []const u8, allocator: Allocator) ![32]u8 {
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();
    try concatenated.appendSlice(&aggregated_pubkey.toBytes());
    for (group_nonces.*) |group_nonce| {
        try concatenated.appendSlice(&group_nonce.toBytes());
    }
    try concatenated.appendSlice(message);
    const concatenated_slice = try concatenated.toOwnedSlice();

    var out: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(concatenated_slice, &out, .{});
    allocator.free(concatenated_slice);
    return out;
}

fn partial_sign(signer_keypair: *const KeyPair, signer_nonces: []KeyPair, aggregated_pubkey: *const AggregatedPubkey, signers_nonces: std.ArrayList([2]Ristretto255), message: []const u8, allocator: Allocator) !schnorr.Signature {

    // []{ r_1 .. r_v }
    const group_nonces = compute_group_nonces(signers_nonces);
    const group_nonces_slice = group_nonces[0..];

    // a_i = H(L || X_i)
    const signer_hash = try compute_signer_hash(aggregated_pubkey.hash, &signer_keypair.pub_point, allocator);

    // b
    const nonce_coeff = try compute_nonce_coeff(&aggregated_pubkey.point, group_nonces_slice, message, allocator);

    const R_0 = group_nonces[0];
    const R_1 = try group_nonces[1].mul(nonce_coeff);
    const R = R_0.add(R_1);

    var s_right: CompressedScalar = signer_nonces[0].priv_key;
    s_right = Ristretto255.scalar.add(s_right, Ristretto255.scalar.mul(signer_nonces[1].priv_key, nonce_coeff));

    const c = try schnorr.compute_signer_nonce_message_hash(&aggregated_pubkey.point, &R, message, allocator);
    var s = Ristretto255.scalar.mul(c, signer_hash);
    s = Ristretto255.scalar.mul(s, signer_keypair.priv_key);
    s = Ristretto255.scalar.add(s, s_right);

    return schnorr.Signature{
        .nonce_pub = R.toBytes(),
        .s = s,
    };
}

fn sign(partial_signatures: std.ArrayList(schnorr.Signature)) !schnorr.Signature {
    std.debug.assert(partial_signatures.items.len > 0);

    var s: CompressedScalar = Ristretto255.scalar.zero;
    const R = partial_signatures.items[0].nonce_pub;
    for (partial_signatures.items) |sig| {
        s = Ristretto255.scalar.add(s, sig.s);
    }
    return schnorr.Signature{ .nonce_pub = R, .s = s };
}

const expect = std.testing.expect;

test "generate 2 nonces" {
    const nonces = try generate_nonces(2);
    try expect(nonces.len == 2);
}

test "successful sign and verify between 3 signers" {
    const message = "test";

    var keypairs = std.ArrayList(KeyPair).init(std.testing.allocator);
    defer keypairs.deinit();
    var pub_keys = std.ArrayList(Ristretto255).init(std.testing.allocator);
    defer pub_keys.deinit();

    var test_nonces = std.ArrayList([2]KeyPair).init(std.testing.allocator);
    defer test_nonces.deinit();
    var test_nonce_points = std.ArrayList([2]Ristretto255).init(std.testing.allocator);
    defer test_nonce_points.deinit();

    for (0..3) |_| {
        const keypair = try schnorr.generate_nonce();
        try keypairs.append(keypair);
        try pub_keys.append(keypair.pub_point);

        const nonce1 = try schnorr.generate_nonce();
        const nonce2 = try schnorr.generate_nonce();

        const nonces = [_]KeyPair{ nonce1, nonce2 };
        const nonce_points = [_]Ristretto255{ nonce1.pub_point, nonce2.pub_point };

        try test_nonces.append(nonces);
        try test_nonce_points.append(nonce_points);
    }

    const aggregate_key = try compute_aggregate_pubkey(pub_keys, std.testing.allocator);

    var partial_sigs = std.ArrayList(schnorr.Signature).init(std.testing.allocator);
    defer partial_sigs.deinit();
    for (0..pub_keys.items.len) |i| {
        const keypair = keypairs.items[i];
        const nonces = &test_nonces.items[i];
        const sig = try partial_sign(&keypair, nonces, &aggregate_key, test_nonce_points, message, std.testing.allocator);
        try partial_sigs.append(sig);
    }

    const final_sig = try sign(partial_sigs);
    const final_sig_bytes = final_sig.toBytes();

    const valid = try final_sig.verify(&aggregate_key.point, message, std.testing.allocator);

    std.debug.print("\nsig: {any}, valid: {any} \n", .{ final_sig_bytes, valid });
    try expect(final_sig_bytes.len == 64);
}
