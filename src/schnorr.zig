const std = @import("std");
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512;

const KeyPair = struct {
    pub_point: Ristretto255,
    priv_key: [32]u8,
};

fn get_rand_nonce() !KeyPair {
    var rand_scalar: [32]u8 = undefined;
    for (0..32) |i| {
        rand_scalar[i] = std.crypto.random.intRangeAtMost(u8, 1, 255);
    }
    const base_point = std.crypto.ecc.Ristretto255.basePoint;
    const rand_pub = try std.crypto.ecc.Ristretto255.mul(base_point, rand_scalar);
    return KeyPair{
        .pub_point = rand_pub,
        .priv_key = rand_scalar,
    };
}

fn sign(message: []const u8, key_pair: *KeyPair, allocator: Allocator) ![Sha512.digest_length]u8 {
    var out: [Sha512.digest_length]u8 = undefined;

    const rand_nonce = try get_rand_nonce();
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();
    try concatenated.appendSlice(&rand_nonce.pub_point.toBytes());
    // try concatenated.appendSlice(rand_pub.toBytes());
    try concatenated.appendSlice(&key_pair.pub_point.toBytes());
    try concatenated.appendSlice(message);

    const concatenated_slice = try concatenated.toOwnedSlice();
    Sha512.hash(concatenated_slice, &out, .{});
    allocator.free(concatenated_slice);

    return out;
}

test "signing" {
    const message: []const u8 = "test";

    var key = try get_rand_nonce();
    _ = try sign(message, &key, std.testing.allocator);
}
