const std = @import("std");
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512_256;
const CompressedScalar = Ristretto255.scalar.CompressedScalar;

const KeyPair = struct {
    pub_point: Ristretto255,
    priv_key: CompressedScalar,
};

fn get_rand_nonce() !KeyPair {
    var rand_scalar: CompressedScalar = undefined;
    for (0..32) |i| {
        rand_scalar[i] = std.crypto.random.intRangeAtMost(u8, 0, 255);
    }
    const rand_pub = try Ristretto255.basePoint.mul(rand_scalar);
    return KeyPair{
        .pub_point = rand_pub,
        .priv_key = rand_scalar,
    };
}

fn get_rpm_hash(nonce_pub: *const Ristretto255, signer_pub: *const Ristretto255, message: []const u8, allocator: Allocator) ![32]u8 {
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();
    try concatenated.appendSlice(&nonce_pub.toBytes());
    try concatenated.appendSlice(&signer_pub.toBytes());
    try concatenated.appendSlice(message);
    const concatenated_slice = try concatenated.toOwnedSlice();

    var out: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(concatenated_slice, &out, .{});
    allocator.free(concatenated_slice);
    return out;
}

pub const Signature = struct {
    nonce_pub: CompressedScalar,
    s: CompressedScalar,

    const Self = @This();

    /// Signs a message using a simple Schnorr signature scheme:
    /// (R,s) = rG, r + H(X,R,m) * x
    ///
    /// R: random nonce point (rG), r: random nonce secret
    /// X: signer point (xG), x: signer secret
    ///
    /// # Arguments
    ///
    /// * `message` - The message to be signed.
    /// * `key_pair` - The key pair for signing.
    ///
    /// # Returns
    ///
    /// A Signature struct containing `nonce_pub` (in bytes) and `s`.
    ///
    pub fn sign(message: []const u8, signer_priv: *CompressedScalar, allocator: Allocator) !Self {
        const signer_point = try Ristretto255.basePoint.mul(signer_priv.*);
        const rand_nonce = try get_rand_nonce();
        // H(X,R,m)
        const hash = try get_rpm_hash(&rand_nonce.pub_point, &signer_point, message, allocator);
        // s = r + H(X,R,m) * x
        const s = Ristretto255.scalar.add(rand_nonce.priv_key, Ristretto255.scalar.mul(hash, signer_priv.*));
        return Signature{ .nonce_pub = rand_nonce.pub_point.toBytes(), .s = s };
    }

    pub fn verify(self: *const Self, signer_pub: *const Ristretto255, message: []const u8, allocator: Allocator) !bool {
        const nonce_point = try Ristretto255.fromBytes(self.nonce_pub);
        const hash = try get_rpm_hash(&nonce_point, signer_pub, message, allocator);
        const left = try Ristretto255.basePoint.mul(self.s);
        // IMPORTANT: calculations MUST be done on Ristretto255
        // POINTS, not the underlying raw bytes
        const hash_signer_point = try signer_pub.mul(hash);
        const right = hash_signer_point.add(nonce_point);
        return left.equivalent(right);
    }
};

const assert = std.debug.assert;
test "signing verification success" {
    const message: []const u8 = "test";
    var key = try get_rand_nonce();
    const sig = try Signature.sign(message, &key.priv_key, std.testing.allocator);
    const verified = try sig.verify(&key.pub_point, message, std.testing.allocator);
    assert(verified);
}

test "signing verification failed, invalid signer public key" {
    const message: []const u8 = "test";
    var key = try get_rand_nonce();
    const sig = try Signature.sign(message, &key.priv_key, std.testing.allocator);
    var key2 = try get_rand_nonce();
    const verified = try sig.verify(&key2.pub_point, message, std.testing.allocator);
    assert(!verified);
}

test "signing verification failed, invalid message" {
    const message: []const u8 = "test";
    const message2: []const u8 = "test2";
    var key = try get_rand_nonce();
    const sig = try Signature.sign(message, &key.priv_key, std.testing.allocator);
    const verified = try sig.verify(&key.pub_point, message2, std.testing.allocator);
    assert(!verified);
}
