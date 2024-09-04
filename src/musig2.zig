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
/// # Inputs:
/// - `public_keys`: an array of public keys
///
/// # Returns:
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
/// Arguments:
/// - `pubkeys_hash`: hash of all signers public keys
///
/// Returns:
/// - L value as a `Scalar`
fn compute_signer_hash(pubkeys_hash: [32]u8, signer_pubkey: Ristretto255, allocator: Allocator) ![32]u8 {
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

/// Computes the aggregate public key X via sum of all a_i * X_i
///
/// Inputs:
/// - `pubkeys`: an array of public keys as Ristretto255 points
///
/// Returns:
/// - aggregate public key X as a Ristretto255 point
fn compute_aggregate_pubkey(pubkeys: std.ArrayList(Ristretto255), allocator: Allocator) !Ristretto255 {
    std.debug.assert(pubkeys.items.len > 0);

    var aggregated_pubkey: ?Ristretto255 = null;
    const L = try compute_pubkeys_hash(pubkeys, allocator);
    for (pubkeys.items) |pub_key| {
        const a_i = try compute_signer_hash(L, pub_key, allocator);
        const point: Ristretto255 = try pub_key.mul(a_i);
        if (aggregated_pubkey == null) {
            aggregated_pubkey = point;
            continue;
        }
        aggregated_pubkey.? = aggregated_pubkey.?.add(point);
    }
    return aggregated_pubkey.?;
}

const expect = std.testing.expect;

test "generate 2 nonces" {
    const nonces = try generate_nonces(2);
    try expect(nonces.len == 2);
}

test "compute aggregated public key" {
    const test1 = try schnorr.generate_nonce();
    const test2 = try schnorr.generate_nonce();
    const test3 = try schnorr.generate_nonce();
    var pub_keys = std.ArrayList(Ristretto255).init(std.testing.allocator);
    defer pub_keys.deinit();
    try pub_keys.append(test1.pub_point);
    try pub_keys.append(test2.pub_point);
    try pub_keys.append(test3.pub_point);
    const aggregated = try compute_aggregate_pubkey(pub_keys, std.testing.allocator);
    std.debug.print("\naggregated: {any}\n", .{aggregated});

    try expect(aggregated.toBytes().len == 32);
}
