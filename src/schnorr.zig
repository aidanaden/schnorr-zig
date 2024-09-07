const std = @import("std");
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512_256;
const CompressedScalar = Ristretto255.scalar.CompressedScalar;

pub const KeyPair = struct {
    pub_point: Ristretto255,
    priv_key: CompressedScalar,
};

pub fn generate_keypair() !KeyPair {
    var rand_scalar: CompressedScalar = undefined;
    for (0..32) |i| {
        rand_scalar[i] = std.crypto.random.intRangeAtMost(u8, 1, 255);
    }
    const rand_pub = try Ristretto255.basePoint.mul(rand_scalar);
    return KeyPair{
        .pub_point = rand_pub,
        .priv_key = rand_scalar,
    };
}

pub fn compute_signer_nonce_message_hash(signer_point: *const Ristretto255, nonce_point: *const Ristretto255, message: []const u8, allocator: Allocator) ![32]u8 {
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();
    try concatenated.appendSlice(&signer_point.toBytes());
    try concatenated.appendSlice(&nonce_point.toBytes());
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
    ///
    /// ```
    /// R = rG
    /// (R,s) = R, r + H(X||R||M) * x
    /// ````
    ///
    /// R: nonce point (rG), r: random nonce secret
    /// X: signer point (xG), x: signer secret
    ///
    /// Note: only difference between this implementation and Ed25519
    /// is Ed25519 generates the nonce via Sha512 with the message.
    ///
    /// ```
    /// r = H(r || m)
    /// R = rG
    /// (R,s) = rG, r + H(X||R||M) * x
    /// ````
    ///
    ///
    /// Arguments
    /// - `message`: The message to be signed.
    /// - `key_pair`: The key pair for signing.
    ///
    /// Returns
    /// - A Signature struct containing `nonce_pub` (in bytes) and `s`.
    pub fn sign(message: []const u8, signer_priv: *const CompressedScalar, allocator: Allocator) !Self {
        const signer_point = try Ristretto255.basePoint.mul(signer_priv.*);
        const nonce = try generate_keypair();
        // H(X,R,m)
        const hash = try compute_signer_nonce_message_hash(&signer_point, &nonce.pub_point, message, allocator);
        // s = r + H(X,R,m) * x
        const s = Ristretto255.scalar.add(nonce.priv_key, Ristretto255.scalar.mul(hash, signer_priv.*));
        return Signature{ .nonce_pub = nonce.pub_point.toBytes(), .s = s };
    }

    /// Verifies a Schnorr signature given a signer's
    /// public key and an expected message
    ///
    /// ```
    /// sG === (r + H(X||R||M) * x)G
    /// sG === rG + (H(X||R||M) * x)G
    /// sG === R + H(X||R||M) * (xG)
    /// sG === R + H(X||R||M) * X
    /// ```
    ///
    /// R: nonce point (rG)
    /// X: signer point (xG)
    ///
    /// Arguments
    /// - `signer_pub`: Signer's public key (X)
    /// - `message`: Message to verify signature for
    ///
    /// Returns
    /// - Boolean indicating if given signature (R, s) is valid
    pub fn verify(self: *const Self, signer_pub: *const Ristretto255, message: []const u8, allocator: Allocator) !bool {
        // sG
        const left = try Ristretto255.basePoint.mul(self.s);
        // R
        const nonce_point = try Ristretto255.fromBytes(self.nonce_pub);
        // H(X||R||M)
        const hash = try compute_signer_nonce_message_hash(signer_pub, &nonce_point, message, allocator);
        // H(X||R||M) * X
        const hash_signer_point = try signer_pub.mul(hash);
        // R + H(X||R||M|) * X
        const right = hash_signer_point.add(nonce_point);
        // sG === R + H(X||R||M) * X
        return left.equivalent(right);
    }

    pub fn fromBytes(bytes: *const [64]u8) Self {
        return Self{ .nonce_pub = bytes[0..32], .s = bytes[32..] };
    }

    pub fn toBytes(self: *const Self) [64]u8 {
        const bytes = self.nonce_pub ++ self.s;
        return bytes;
    }

    pub fn print_hex(self: *const Self, writer: std.io.AnyWriter) !void {
        for (0..self.nonce_pub.len) |i| {
            try writer.print("{X:0>2}", .{self.nonce_pub[i]});
        }
        for (0..self.s.len) |i| {
            try writer.print("{X:0>2}", .{self.s[i]});
        }
    }
};

const expect = std.testing.expect;

test "signing verification success" {
    const message: []const u8 = "test";
    var key = try generate_keypair();
    const sig = try Signature.sign(message, &key.priv_key, std.testing.allocator);
    const verified = try sig.verify(&key.pub_point, message, std.testing.allocator);
    std.debug.print("\nschnorr single sign success: {any}", .{verified});
    try expect(verified);
}

test "signing verification failed, invalid signer public key" {
    const message: []const u8 = "test";
    var key = try generate_keypair();
    const sig = try Signature.sign(message, &key.priv_key, std.testing.allocator);
    var key2 = try generate_keypair();
    const verified = try sig.verify(&key2.pub_point, message, std.testing.allocator);
    try expect(!verified);
}

test "signing verification failed, invalid message" {
    const message: []const u8 = "test";
    const message2: []const u8 = "test2";
    var key = try generate_keypair();
    const sig = try Signature.sign(message, &key.priv_key, std.testing.allocator);
    const verified = try sig.verify(&key.pub_point, message2, std.testing.allocator);
    try expect(!verified);
}
