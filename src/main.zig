const std = @import("std");
const yazap = @import("yazap");
const schnorr = @import("schnorr.zig");
const musig2 = @import("musig2.zig");
const Ristretto255 = std.crypto.ecc.Ristretto255;

const App = yazap.App;
const Arg = yazap.Arg;

fn parse_raw_hex(raw_input: []const u8, comptime output_size: u32) ![output_size]u8 {
    std.debug.assert(raw_input.len == output_size * 2);
    var buffer: [output_size]u8 = undefined;
    var i: usize = 0;
    while (i < raw_input.len) : (i += 2) {
        const raw_hex = raw_input[i .. i + 2];
        const hex = try std.fmt.parseInt(u8, raw_hex, 16);
        buffer[i / 2] = hex;
    }
    return buffer;
}

pub fn main() !void {
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var app = App.init(allocator, "schnorr", "Schnorr Signing (via Ristretto255) CLI tool");
    defer app.deinit();

    var cli = app.rootCommand();

    var sign_cmd = app.createCommand("sign", "Sign a message given a private key");
    try sign_cmd.addArg(Arg.singleValueOption("priv", 'p', "Private key for signing"));
    try sign_cmd.addArg(Arg.singleValueOption("message", 'm', "Message to sign"));

    var verify_cmd = app.createCommand("verify", "Verify a signature given the signer's public key");
    try verify_cmd.addArg(Arg.singleValueOption("pub", 'p', "Signer's public key"));
    try verify_cmd.addArg(Arg.singleValueOption("message", 'm', "Message used to generate signature"));
    try verify_cmd.addArg(Arg.singleValueOption("signature", 's', "Signature to verify"));

    try cli.addSubcommand(sign_cmd);
    try cli.addSubcommand(verify_cmd);

    const matches = try app.parseProcess();

    // `Sign` subcommand setup
    if (matches.subcommandMatches("sign")) |sign_cmd_matches| {
        if (sign_cmd_matches.getSingleValue("priv") == null) {
            try stdout.print("Please provide private key for signing", .{});
            try bw.flush();
            return;
        }
        if (sign_cmd_matches.getSingleValue("message") == null) {
            try stdout.print("Please provide message to sign", .{});
            try bw.flush();
            return;
        }

        const raw_privkey = sign_cmd_matches.getSingleValue("priv").?;
        const message = sign_cmd_matches.getSingleValue("message").?;

        const privkey = try parse_raw_hex(raw_privkey, 32);
        const pubkey = try Ristretto255.basePoint.mul(privkey);
        const pubkey_bytes = pubkey.toBytes();
        try stdout.print("pub key:  ", .{});
        for (0..pubkey_bytes.len) |i| {
            try stdout.print("{X:0>2}", .{pubkey_bytes[i]});
        }

        const sig = try schnorr.Signature.sign(message, &privkey, allocator);
        try stdout.print("\nsignature:  ", .{});
        for (0..sig.nonce_pub.len) |i| {
            try stdout.print("{X:0>2}", .{sig.nonce_pub[i]});
        }
        for (0..sig.s.len) |i| {
            try stdout.print("{X:0>2}", .{sig.s[i]});
        }
        try bw.flush();
    }

    // `Verify` subcommand setup
    if (matches.subcommandMatches("verify")) |verify_cmd_matches| {
        if (verify_cmd_matches.getSingleValue("pub") == null) {
            try stdout.print("Please provide signer's public key", .{});
            try bw.flush();
            return;
        }
        if (verify_cmd_matches.getSingleValue("message") == null) {
            try stdout.print("Please provide message to sign", .{});
            try bw.flush();
            return;
        }
        if (verify_cmd_matches.getSingleValue("signature") == null) {
            try stdout.print("Please provide signature to verify", .{});
            try bw.flush();
            return;
        }

        const raw_message = verify_cmd_matches.getSingleValue("message").?;
        const raw_pubkey = verify_cmd_matches.getSingleValue("pub").?;
        const raw_sig = verify_cmd_matches.getSingleValue("signature").?;

        const pubkey_bytes = try parse_raw_hex(raw_pubkey, 32);
        const pubkey = try Ristretto255.fromBytes(pubkey_bytes);
        const sig_bytes = try parse_raw_hex(raw_sig, 64);

        var sig_nonce_pubkey: [32]u8 = undefined;
        const sig_nonce_pubkey_slice = sig_nonce_pubkey[0..];
        var sig_s: [32]u8 = undefined;
        const sig_s_slice = sig_s[0..];

        std.mem.copyForwards(u8, sig_nonce_pubkey_slice, sig_bytes[0..32]);
        std.mem.copyForwards(u8, sig_s_slice, sig_bytes[32..]);

        const sig = schnorr.Signature{ .nonce_pub = sig_nonce_pubkey, .s = sig_s };
        const valid = try sig.verify(&pubkey, raw_message, allocator);

        try stdout.print("signature validity: {any}", .{valid});
        try bw.flush();
    }
}

test {
    @import("std").testing.refAllDecls(musig2);
    @import("std").testing.refAllDecls(schnorr);
}
